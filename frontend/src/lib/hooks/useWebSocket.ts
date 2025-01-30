import { useEffect, useRef, useState, useCallback } from 'react'
import { useSession } from 'next-auth/react'

interface WebSocketMessage {
  type: string
  data: any
}

interface UseWebSocketOptions {
  channel: string
  onMessage?: (message: WebSocketMessage) => void
  reconnectInterval?: number
  maxReconnectAttempts?: number
}

export function useWebSocket({
  channel,
  onMessage,
  reconnectInterval = 5000,
  maxReconnectAttempts = 5
}: UseWebSocketOptions) {
  const { data: session } = useSession()
  const [isConnected, setIsConnected] = useState(false)
  const [error, setError] = useState<Error | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectAttemptsRef = useRef(0)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout>()
  
  const connect = useCallback(() => {
    try {
      if (!session?.accessToken) return
      
      // Close existing connection
      if (wsRef.current) {
        wsRef.current.close()
      }
      
      // Create new connection
      const ws = new WebSocket(
        `${process.env.NEXT_PUBLIC_WS_URL}/ws/${channel}`
      )
      
      ws.onopen = () => {
        console.log(`WebSocket connected to ${channel}`)
        setIsConnected(true)
        setError(null)
        reconnectAttemptsRef.current = 0
        
        // Send authentication token
        ws.send(JSON.stringify({
          type: 'auth',
          token: session.accessToken
        }))
      }
      
      ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data)
          
          // Handle ping/pong
          if (message.type === 'ping') {
            ws.send(JSON.stringify({ type: 'pong' }))
            return
          }
          
          // Handle other messages
          onMessage?.(message)
        } catch (err) {
          console.error('Failed to parse WebSocket message:', err)
        }
      }
      
      ws.onclose = () => {
        console.log(`WebSocket disconnected from ${channel}`)
        setIsConnected(false)
        wsRef.current = null
        
        // Attempt reconnection
        if (reconnectAttemptsRef.current < maxReconnectAttempts) {
          reconnectTimeoutRef.current = setTimeout(() => {
            reconnectAttemptsRef.current++
            connect()
          }, reconnectInterval)
        } else {
          setError(new Error('Max reconnection attempts reached'))
        }
      }
      
      ws.onerror = (event) => {
        console.error('WebSocket error:', event)
        setError(new Error('WebSocket connection error'))
      }
      
      // Store reference
      wsRef.current = ws
      
      // Start heartbeat
      const heartbeat = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'ping' }))
        }
      }, 30000)
      
      return () => {
        clearInterval(heartbeat)
      }
    } catch (err) {
      console.error('Failed to create WebSocket connection:', err)
      setError(err as Error)
    }
  }, [channel, session, onMessage, reconnectInterval, maxReconnectAttempts])
  
  useEffect(() => {
    connect()
    
    return () => {
      // Clean up on unmount
      if (wsRef.current) {
        wsRef.current.close()
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
      }
    }
  }, [connect])
  
  const send = useCallback((message: any) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message))
    } else {
      console.warn('WebSocket is not connected')
    }
  }, [])
  
  return {
    isConnected,
    error,
    send
  }
} 