import { usePathname } from 'next/navigation'
import Link from 'next/link'
import {
  HomeIcon,
  ShieldExclamationIcon,
  BoltIcon,
  ChartBarIcon,
  ServerIcon,
  CpuChipIcon,
  Cog6ToothIcon
} from '@heroicons/react/24/outline'
import { usePermissions } from '@/lib/auth'

const navigation = [
  {
    name: 'Dashboard',
    href: '/dashboard',
    icon: HomeIcon,
    permission: 'dashboard:view'
  },
  {
    name: 'Alerts',
    href: '/alerts',
    icon: ShieldExclamationIcon,
    permission: 'alerts:view'
  },
  {
    name: 'Offensive',
    href: '/offensive',
    icon: BoltIcon,
    permission: 'offensive:view'
  },
  {
    name: 'Defensive',
    href: '/defensive',
    icon: ServerIcon,
    permission: 'defensive:view'
  },
  {
    name: 'Analytics',
    href: '/analytics',
    icon: ChartBarIcon,
    permission: 'analytics:view'
  },
  {
    name: 'AI/ML',
    href: '/ai',
    icon: CpuChipIcon,
    permission: 'ai:view'
  },
  {
    name: 'Settings',
    href: '/settings',
    icon: Cog6ToothIcon,
    permission: 'settings:view'
  }
]

export default function Sidebar() {
  const pathname = usePathname()
  const { hasPermission } = usePermissions()
  
  return (
    <div className="flex h-screen w-64 flex-col border-r border-gray-200 bg-white dark:border-gray-700 dark:bg-gray-800">
      <div className="flex flex-1 flex-col overflow-y-auto pt-5 pb-4">
        <nav className="mt-5 flex-1 space-y-1 px-2">
          {navigation.map((item) => {
            // Skip items user doesn't have permission for
            if (!hasPermission(item.permission)) {
              return null
            }
            
            const isActive = pathname === item.href
            
            return (
              <Link
                key={item.name}
                href={item.href}
                className={`
                  group flex items-center rounded-md px-2 py-2 text-sm font-medium
                  ${
                    isActive
                      ? 'bg-gray-100 text-gray-900 dark:bg-gray-700 dark:text-white'
                      : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900 dark:text-gray-300 dark:hover:bg-gray-700 dark:hover:text-white'
                  }
                `}
              >
                <item.icon
                  className={`
                    mr-3 h-5 w-5 flex-shrink-0
                    ${
                      isActive
                        ? 'text-gray-500 dark:text-gray-300'
                        : 'text-gray-400 group-hover:text-gray-500 dark:text-gray-400 dark:group-hover:text-gray-300'
                    }
                  `}
                />
                {item.name}
              </Link>
            )
          })}
        </nav>
      </div>
      
      {/* Status Indicator */}
      <div className="flex items-center justify-between border-t border-gray-200 p-4 dark:border-gray-700">
        <div className="flex items-center">
          <div className="h-2 w-2 rounded-full bg-green-400" />
          <span className="ml-2 text-sm text-gray-500 dark:text-gray-400">
            System Healthy
          </span>
        </div>
      </div>
    </div>
  )
} 