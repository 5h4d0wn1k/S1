import { Fragment } from 'react'
import Link from 'next/link'
import { Menu, Transition } from '@headlessui/react'
import {
  BellIcon,
  UserCircleIcon,
  Cog6ToothIcon,
  ArrowRightOnRectangleIcon
} from '@heroicons/react/24/outline'
import { useTheme } from 'next-themes'
import { User } from '@/lib/types'
import { signOut } from '@/lib/auth'

interface NavbarProps {
  user: User
}

export default function Navbar({ user }: NavbarProps) {
  const { theme, setTheme } = useTheme()
  
  return (
    <nav className="bg-white dark:bg-gray-800 shadow-sm">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="flex h-16 justify-between">
          {/* Logo */}
          <div className="flex items-center">
            <Link
              href="/dashboard"
              className="flex items-center space-x-2"
            >
              <img
                src="/logo.svg"
                alt="SIEM Logo"
                className="h-8 w-8"
              />
              <span className="text-xl font-bold text-gray-900 dark:text-white">
                SIEM
              </span>
            </Link>
          </div>
          
          {/* Right Navigation */}
          <div className="flex items-center space-x-4">
            {/* Theme Toggle */}
            <button
              onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
              className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
            >
              {theme === 'dark' ? (
                <svg
                  className="h-5 w-5"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"
                  />
                </svg>
              ) : (
                <svg
                  className="h-5 w-5"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"
                  />
                </svg>
              )}
            </button>
            
            {/* Notifications */}
            <button className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200">
              <BellIcon className="h-5 w-5" />
            </button>
            
            {/* Profile Dropdown */}
            <Menu as="div" className="relative">
              <Menu.Button className="flex items-center space-x-2 rounded-full bg-white p-1 text-gray-500 hover:text-gray-700 dark:bg-gray-800 dark:text-gray-400 dark:hover:text-gray-200">
                <UserCircleIcon className="h-8 w-8" />
              </Menu.Button>
              
              <Transition
                as={Fragment}
                enter="transition ease-out duration-100"
                enterFrom="transform opacity-0 scale-95"
                enterTo="transform opacity-100 scale-100"
                leave="transition ease-in duration-75"
                leaveFrom="transform opacity-100 scale-100"
                leaveTo="transform opacity-0 scale-95"
              >
                <Menu.Items className="absolute right-0 mt-2 w-48 origin-top-right rounded-md bg-white py-1 shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none dark:bg-gray-800">
                  <div className="px-4 py-2">
                    <p className="text-sm text-gray-700 dark:text-gray-300">
                      {user.username}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      {user.email}
                    </p>
                  </div>
                  
                  <Menu.Item>
                    {({ active }) => (
                      <Link
                        href="/settings"
                        className={`
                          flex items-center px-4 py-2 text-sm
                          ${
                            active
                              ? 'bg-gray-100 text-gray-900 dark:bg-gray-700 dark:text-white'
                              : 'text-gray-700 dark:text-gray-300'
                          }
                        `}
                      >
                        <Cog6ToothIcon className="mr-3 h-5 w-5" />
                        Settings
                      </Link>
                    )}
                  </Menu.Item>
                  
                  <Menu.Item>
                    {({ active }) => (
                      <button
                        onClick={() => signOut()}
                        className={`
                          flex w-full items-center px-4 py-2 text-sm
                          ${
                            active
                              ? 'bg-gray-100 text-gray-900 dark:bg-gray-700 dark:text-white'
                              : 'text-gray-700 dark:text-gray-300'
                          }
                        `}
                      >
                        <ArrowRightOnRectangleIcon className="mr-3 h-5 w-5" />
                        Sign out
                      </button>
                    )}
                  </Menu.Item>
                </Menu.Items>
              </Transition>
            </Menu>
          </div>
        </div>
      </div>
    </nav>
  )
} 