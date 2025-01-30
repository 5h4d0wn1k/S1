import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

import numpy as np
import torch
from pydantic import BaseModel, Field
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    pipeline
)

from ...core.exceptions import MLPipelineError
from ...utils.logging import LoggerMixin

class PredictionResult(BaseModel):
    """Result of a model prediction."""
    id: UUID = Field(default_factory=uuid4)
    model_type: str
    input_data: Dict[str, Any]
    prediction: Any
    confidence: float
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)

class ModelMetrics(BaseModel):
    """Model performance metrics."""
    model_type: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    latency_ms: float
    last_updated: datetime = Field(default_factory=datetime.utcnow)

class MLPipeline(LoggerMixin):
    """Manages AI/ML models for security analytics."""
    
    def __init__(self) -> None:
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.models: Dict[str, Any] = {}
        self.tokenizers: Dict[str, Any] = {}
        self.metrics: Dict[str, ModelMetrics] = {}
        self.running = False
        
        # Queues for batch processing
        self.prediction_queue: asyncio.Queue = asyncio.Queue()
        self.training_queue: asyncio.Queue = asyncio.Queue()
    
    async def start(self) -> None:
        """Start the ML pipeline."""
        try:
            self.running = True
            self.log_info("ML pipeline started")
            
            # Initialize models
            await self._init_models()
            
            # Start background tasks
            asyncio.create_task(self._process_predictions())
            asyncio.create_task(self._process_training())
            asyncio.create_task(self._monitor_performance())
        except Exception as e:
            self.log_error("Failed to start ML pipeline", e)
            raise MLPipelineError("Pipeline startup failed")
    
    async def stop(self) -> None:
        """Stop the ML pipeline."""
        try:
            self.running = False
            self.log_info("ML pipeline stopped")
        except Exception as e:
            self.log_error("Failed to stop ML pipeline", e)
            raise MLPipelineError("Pipeline shutdown failed")
    
    async def predict_threat(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None
    ) -> PredictionResult:
        """Predict if text contains security threats."""
        try:
            model_type = "threat_detection"
            
            if model_type not in self.models:
                raise MLPipelineError(f"Model {model_type} not loaded")
            
            # Tokenize input
            tokens = self.tokenizers[model_type](
                text,
                truncation=True,
                padding=True,
                return_tensors="pt"
            ).to(self.device)
            
            # Get prediction
            with torch.no_grad():
                outputs = self.models[model_type](**tokens)
                probabilities = torch.softmax(outputs.logits, dim=1)
                prediction = torch.argmax(probabilities, dim=1).item()
                confidence = probabilities[0][prediction].item()
            
            result = PredictionResult(
                model_type=model_type,
                input_data={"text": text},
                prediction=prediction,
                confidence=confidence,
                metadata={"context": context} if context else {}
            )
            
            self.log_info(
                "Threat prediction completed",
                prediction=prediction,
                confidence=confidence
            )
            
            return result
        except Exception as e:
            self.log_error(
                "Threat prediction failed",
                error=e,
                text=text
            )
            raise MLPipelineError("Threat prediction failed")
    
    async def detect_anomaly(
        self,
        features: List[float],
        context: Optional[Dict[str, Any]] = None
    ) -> PredictionResult:
        """Detect anomalies in numerical features."""
        try:
            model_type = "anomaly_detection"
            
            if model_type not in self.models:
                raise MLPipelineError(f"Model {model_type} not loaded")
            
            # Convert to tensor
            x = torch.tensor(features, dtype=torch.float32).to(self.device)
            
            # Get prediction
            with torch.no_grad():
                reconstruction = self.models[model_type](x.unsqueeze(0))
                mse = torch.mean((x - reconstruction.squeeze(0)) ** 2).item()
                is_anomaly = mse > self.models[model_type].threshold
                confidence = 1.0 - (mse / self.models[model_type].threshold)
            
            result = PredictionResult(
                model_type=model_type,
                input_data={"features": features},
                prediction=bool(is_anomaly),
                confidence=float(confidence),
                metadata={
                    "mse": mse,
                    "threshold": self.models[model_type].threshold,
                    "context": context
                } if context else {
                    "mse": mse,
                    "threshold": self.models[model_type].threshold
                }
            )
            
            self.log_info(
                "Anomaly detection completed",
                is_anomaly=is_anomaly,
                mse=mse
            )
            
            return result
        except Exception as e:
            self.log_error(
                "Anomaly detection failed",
                error=e,
                features=features
            )
            raise MLPipelineError("Anomaly detection failed")
    
    async def analyze_query(
        self,
        query: str,
        context: Optional[Dict[str, Any]] = None
    ) -> PredictionResult:
        """Analyze natural language security queries."""
        try:
            model_type = "query_analysis"
            
            if model_type not in self.models:
                raise MLPipelineError(f"Model {model_type} not loaded")
            
            # Use question-answering pipeline
            qa_pipeline = pipeline(
                "question-answering",
                model=self.models[model_type],
                tokenizer=self.tokenizers[model_type],
                device=0 if self.device.type == "cuda" else -1
            )
            
            # Get answer
            result = qa_pipeline(
                question=query,
                context=context.get("context", "") if context else ""
            )
            
            prediction_result = PredictionResult(
                model_type=model_type,
                input_data={"query": query},
                prediction=result["answer"],
                confidence=result["score"],
                metadata={
                    "start": result["start"],
                    "end": result["end"],
                    "context": context
                } if context else {
                    "start": result["start"],
                    "end": result["end"]
                }
            )
            
            self.log_info(
                "Query analysis completed",
                query=query,
                answer=result["answer"],
                confidence=result["score"]
            )
            
            return prediction_result
        except Exception as e:
            self.log_error(
                "Query analysis failed",
                error=e,
                query=query
            )
            raise MLPipelineError("Query analysis failed")
    
    async def _init_models(self) -> None:
        """Initialize ML models."""
        try:
            # Threat detection model
            self.models["threat_detection"] = (
                AutoModelForSequenceClassification
                .from_pretrained("microsoft/mdeberta-v3-base")
                .to(self.device)
            )
            self.tokenizers["threat_detection"] = AutoTokenizer.from_pretrained(
                "microsoft/mdeberta-v3-base"
            )
            
            # Anomaly detection model (custom autoencoder)
            class Autoencoder(torch.nn.Module):
                def __init__(self, input_dim: int):
                    super().__init__()
                    self.encoder = torch.nn.Sequential(
                        torch.nn.Linear(input_dim, 64),
                        torch.nn.ReLU(),
                        torch.nn.Linear(64, 32),
                        torch.nn.ReLU(),
                        torch.nn.Linear(32, 16)
                    )
                    self.decoder = torch.nn.Sequential(
                        torch.nn.Linear(16, 32),
                        torch.nn.ReLU(),
                        torch.nn.Linear(32, 64),
                        torch.nn.ReLU(),
                        torch.nn.Linear(64, input_dim)
                    )
                    self.threshold = 0.1  # Dynamic threshold
                
                def forward(self, x):
                    x = self.encoder(x)
                    x = self.decoder(x)
                    return x
            
            self.models["anomaly_detection"] = Autoencoder(input_dim=100).to(self.device)
            
            # Query analysis model
            self.models["query_analysis"] = (
                AutoModelForSequenceClassification
                .from_pretrained("deepset/roberta-base-squad2")
                .to(self.device)
            )
            self.tokenizers["query_analysis"] = AutoTokenizer.from_pretrained(
                "deepset/roberta-base-squad2"
            )
            
            self.log_info(
                "Models initialized",
                device=self.device.type,
                models=list(self.models.keys())
            )
        except Exception as e:
            self.log_error("Model initialization failed", e)
            raise MLPipelineError("Model initialization failed")
    
    async def _process_predictions(self) -> None:
        """Process prediction requests in batches."""
        while self.running:
            try:
                # Collect batch of predictions
                batch = []
                try:
                    while len(batch) < 32:  # Max batch size
                        item = await asyncio.wait_for(
                            self.prediction_queue.get(),
                            timeout=0.1
                        )
                        batch.append(item)
                except asyncio.TimeoutError:
                    if not batch:
                        continue
                
                # Process batch
                model_type = batch[0]["model_type"]
                if model_type == "threat_detection":
                    await self._batch_predict_threats(batch)
                elif model_type == "anomaly_detection":
                    await self._batch_detect_anomalies(batch)
                
                # Mark tasks as done
                for _ in batch:
                    self.prediction_queue.task_done()
            except Exception as e:
                self.log_error("Prediction processing failed", e)
                await asyncio.sleep(1)
    
    async def _process_training(self) -> None:
        """Process model training requests."""
        while self.running:
            try:
                training_data = await self.training_queue.get()
                
                # Here you would implement model fine-tuning
                model_type = training_data["model_type"]
                if model_type == "threat_detection":
                    await self._train_threat_model(training_data)
                elif model_type == "anomaly_detection":
                    await self._train_anomaly_model(training_data)
                
                self.training_queue.task_done()
            except Exception as e:
                self.log_error("Training processing failed", e)
                await asyncio.sleep(1)
    
    async def _monitor_performance(self) -> None:
        """Monitor model performance metrics."""
        while self.running:
            try:
                for model_type, model in self.models.items():
                    # Calculate and update metrics
                    metrics = await self._calculate_metrics(model_type)
                    self.metrics[model_type] = metrics
                
                await asyncio.sleep(3600)  # Check every hour
            except Exception as e:
                self.log_error("Performance monitoring failed", e)
                await asyncio.sleep(60)
    
    async def _calculate_metrics(self, model_type: str) -> ModelMetrics:
        """Calculate performance metrics for a model."""
        try:
            # Here you would implement metric calculation
            # This is a placeholder implementation
            return ModelMetrics(
                model_type=model_type,
                accuracy=0.95,
                precision=0.93,
                recall=0.94,
                f1_score=0.935,
                latency_ms=10.5
            )
        except Exception as e:
            self.log_error(
                "Metrics calculation failed",
                error=e,
                model_type=model_type
            )
            raise MLPipelineError("Metrics calculation failed")

# Global ML pipeline instance
ml_pipeline = MLPipeline() 