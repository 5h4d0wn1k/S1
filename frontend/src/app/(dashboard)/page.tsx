import { Suspense } from 'react'
import {
  ShieldExclamationIcon,
  BoltIcon,
  ServerIcon,
  ChartBarIcon
} from '@heroicons/react/24/outline'
import { Card } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { AlertsChart } from '@/components/charts/AlertsChart'
import { SecurityScore } from '@/components/metrics/SecurityScore'
import { RecentAlerts } from '@/components/alerts/RecentAlerts'
import { SystemHealth } from '@/components/metrics/SystemHealth'

export default function DashboardPage() {
  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
          Security Dashboard
        </h1>
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
          Real-time overview of your security posture
        </p>
      </div>
      
      {/* Overview Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <div className="flex items-center p-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-red-100 dark:bg-red-900">
              <ShieldExclamationIcon className="h-6 w-6 text-red-600 dark:text-red-200" />
            </div>
            <div className="ml-4">
              <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                Active Alerts
              </h3>
              <Suspense fallback={<Skeleton className="h-8 w-16" />}>
                <p className="mt-1 text-2xl font-semibold text-gray-700 dark:text-gray-200">
                  24
                </p>
              </Suspense>
            </div>
          </div>
        </Card>
        
        <Card>
          <div className="flex items-center p-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-yellow-100 dark:bg-yellow-900">
              <BoltIcon className="h-6 w-6 text-yellow-600 dark:text-yellow-200" />
            </div>
            <div className="ml-4">
              <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                Active Scans
              </h3>
              <Suspense fallback={<Skeleton className="h-8 w-16" />}>
                <p className="mt-1 text-2xl font-semibold text-gray-700 dark:text-gray-200">
                  3
                </p>
              </Suspense>
            </div>
          </div>
        </Card>
        
        <Card>
          <div className="flex items-center p-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-blue-100 dark:bg-blue-900">
              <ServerIcon className="h-6 w-6 text-blue-600 dark:text-blue-200" />
            </div>
            <div className="ml-4">
              <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                Protected Assets
              </h3>
              <Suspense fallback={<Skeleton className="h-8 w-16" />}>
                <p className="mt-1 text-2xl font-semibold text-gray-700 dark:text-gray-200">
                  156
                </p>
              </Suspense>
            </div>
          </div>
        </Card>
        
        <Card>
          <div className="flex items-center p-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-green-100 dark:bg-green-900">
              <ChartBarIcon className="h-6 w-6 text-green-600 dark:text-green-200" />
            </div>
            <div className="ml-4">
              <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                Security Score
              </h3>
              <Suspense fallback={<Skeleton className="h-8 w-16" />}>
                <p className="mt-1 text-2xl font-semibold text-gray-700 dark:text-gray-200">
                  85%
                </p>
              </Suspense>
            </div>
          </div>
        </Card>
      </div>
      
      {/* Charts and Metrics */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <div className="p-4">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
              Alert Trends
            </h3>
            <Suspense fallback={<Skeleton className="h-64" />}>
              <AlertsChart />
            </Suspense>
          </div>
        </Card>
        
        <Card>
          <div className="p-4">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
              Security Score Breakdown
            </h3>
            <Suspense fallback={<Skeleton className="h-64" />}>
              <SecurityScore />
            </Suspense>
          </div>
        </Card>
      </div>
      
      {/* Recent Activity */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <div className="p-4">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
              Recent Alerts
            </h3>
            <Suspense fallback={<Skeleton className="h-64" />}>
              <RecentAlerts />
            </Suspense>
          </div>
        </Card>
        
        <Card>
          <div className="p-4">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
              System Health
            </h3>
            <Suspense fallback={<Skeleton className="h-64" />}>
              <SystemHealth />
            </Suspense>
          </div>
        </Card>
      </div>
    </div>
  )
}

// Metadata
export const metadata = {
  title: 'Dashboard | SIEM',
  description: 'Real-time security monitoring and analytics'
} 