import { ReactNode } from 'react'
import { redirect } from 'next/navigation'
import { getSession } from '@/lib/auth'
import Navbar from '@/components/layout/Navbar'
import Sidebar from '@/components/layout/Sidebar'

interface DashboardLayoutProps {
  children: ReactNode
}

export default async function DashboardLayout({
  children
}: DashboardLayoutProps) {
  const session = await getSession()
  
  if (!session) {
    redirect('/login')
  }
  
  return (
    <div className="min-h-screen bg-gray-100 dark:bg-gray-900">
      <Navbar user={session.user} />
      
      <div className="flex">
        <Sidebar />
        
        <main className="flex-1 p-6">
          <div className="mx-auto max-w-7xl">
            {children}
          </div>
        </main>
      </div>
    </div>
  )
}

// Metadata
export const metadata = {
  title: 'SIEM Dashboard',
  description: 'Next-Generation Security Information and Event Management'
} 