import { useState } from 'react'
import {
  ServerIcon,
  CpuChipIcon,
  CircleStackIcon,
  CloudIcon
} from '@heroicons/react/24/outline'

interface HealthMetric {
  id: string
  name: string
  value: number
  status: 'healthy' | 'warning' | 'critical'
  icon: typeof ServerIcon
}

const mockMetrics: HealthMetric[] = [
  {
    id: '1',
    name: 'CPU Usage',
    value: 45,
    status: 'healthy',
    icon: CpuChipIcon
  },
  {
    id: '2',
    name: 'Memory Usage',
    value: 72,
    status: 'warning',
    icon: CircleStackIcon
  },
  {
    id: '3',
    name: 'Storage',
    value: 65,
    status: 'healthy',
    icon: ServerIcon
  },
  {
    id: '4',
    name: 'Network',
    value: 88,
    status: 'critical',
    icon: CloudIcon
  }
]

export function SystemHealth() {
  const [metrics] = useState<HealthMetric[]>(mockMetrics)
  
  const getStatusColor = (status: HealthMetric['status']) => {
    switch (status) {
      case 'critical':
        return 'text-red-500'
      case 'warning':
        return 'text-yellow-500'
      default:
        return 'text-green-500'
    }
  }
  
  const getProgressColor = (value: number) => {
    if (value >= 90) return 'bg-red-500'
    if (value >= 75) return 'bg-yellow-500'
    return 'bg-green-500'
  }
  
  return (
    <div className="space-y-4">
      {metrics.map((metric) => (
        <div
          key={metric.id}
          className="rounded-lg border border-gray-200 bg-white p-4 dark:border-gray-700 dark:bg-gray-800"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <metric.icon
                className="h-5 w-5 text-gray-400 dark:text-gray-500"
              />
              <span className="text-sm font-medium text-gray-900 dark:text-white">
                {metric.name}
              </span>
            </div>
            <span
              className={`
                flex h-2.5 w-2.5 rounded-full
                ${getStatusColor(metric.status)}
              `}
            />
          </div>
          
          <div className="mt-4">
            <div className="flex items-center justify-between text-sm">
              <span className="text-gray-500 dark:text-gray-400">
                {metric.value}%
              </span>
              <span className="text-gray-500 dark:text-gray-400">
                100%
              </span>
            </div>
            <div className="mt-2 h-2 w-full rounded-full bg-gray-200 dark:bg-gray-700">
              <div
                className={`
                  h-2 rounded-full transition-all
                  ${getProgressColor(metric.value)}
                `}
                style={{ width: `${metric.value}%` }}
              />
            </div>
          </div>
        </div>
      ))}
    </div>
  )
} 