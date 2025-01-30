import { useState } from 'react'
import {
  ShieldExclamationIcon,
  ExclamationTriangleIcon,
  InformationCircleIcon
} from '@heroicons/react/24/outline'
import { formatDistanceToNow } from 'date-fns'

interface Alert {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  source: string
  timestamp: Date
  status: 'open' | 'investigating' | 'resolved'
}

const mockAlerts: Alert[] = [
  {
    id: '1',
    title: 'Potential Data Exfiltration Detected',
    severity: 'critical',
    source: 'Network IDS',
    timestamp: new Date(Date.now() - 1000 * 60 * 5),
    status: 'investigating'
  },
  {
    id: '2',
    title: 'Failed Login Attempts',
    severity: 'high',
    source: 'Authentication Logs',
    timestamp: new Date(Date.now() - 1000 * 60 * 15),
    status: 'open'
  },
  {
    id: '3',
    title: 'Suspicious Process Execution',
    severity: 'medium',
    source: 'Endpoint Agent',
    timestamp: new Date(Date.now() - 1000 * 60 * 30),
    status: 'resolved'
  }
]

export function RecentAlerts() {
  const [alerts] = useState<Alert[]>(mockAlerts)
  
  const getSeverityIcon = (severity: Alert['severity']) => {
    switch (severity) {
      case 'critical':
        return (
          <ShieldExclamationIcon
            className="h-5 w-5 text-red-500"
          />
        )
      case 'high':
        return (
          <ExclamationTriangleIcon
            className="h-5 w-5 text-yellow-500"
          />
        )
      default:
        return (
          <InformationCircleIcon
            className="h-5 w-5 text-blue-500"
          />
        )
    }
  }
  
  const getSeverityClass = (severity: Alert['severity']) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
      case 'high':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
      case 'medium':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200'
      default:
        return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
    }
  }
  
  const getStatusClass = (status: Alert['status']) => {
    switch (status) {
      case 'investigating':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
      case 'resolved':
        return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200'
    }
  }
  
  return (
    <div className="space-y-4">
      {alerts.map((alert) => (
        <div
          key={alert.id}
          className="flex items-start space-x-4 rounded-lg border border-gray-200 bg-white p-4 shadow-sm dark:border-gray-700 dark:bg-gray-800"
        >
          <div className="flex-shrink-0">
            {getSeverityIcon(alert.severity)}
          </div>
          
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between">
              <p className="truncate text-sm font-medium text-gray-900 dark:text-white">
                {alert.title}
              </p>
              <span
                className={`
                  inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium
                  ${getSeverityClass(alert.severity)}
                `}
              >
                {alert.severity}
              </span>
            </div>
            
            <div className="mt-1">
              <p className="text-sm text-gray-500 dark:text-gray-400">
                {alert.source}
              </p>
            </div>
            
            <div className="mt-2 flex items-center justify-between">
              <span className="text-sm text-gray-500 dark:text-gray-400">
                {formatDistanceToNow(alert.timestamp, { addSuffix: true })}
              </span>
              
              <span
                className={`
                  inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium
                  ${getStatusClass(alert.status)}
                `}
              >
                {alert.status}
              </span>
            </div>
          </div>
        </div>
      ))}
    </div>
  )
} 