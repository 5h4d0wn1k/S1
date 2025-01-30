import { useEffect, useRef } from 'react'
import * as echarts from 'echarts'
import { useTheme } from 'next-themes'

export function SecurityScore() {
  const chartRef = useRef<HTMLDivElement>(null)
  const { theme } = useTheme()
  
  useEffect(() => {
    if (!chartRef.current) return
    
    const chart = echarts.init(chartRef.current, theme)
    
    const option = {
      tooltip: {
        trigger: 'item'
      },
      legend: {
        orient: 'vertical',
        right: 10,
        top: 'center',
        textStyle: {
          color: theme === 'dark' ? '#9CA3AF' : '#4B5563'
        }
      },
      series: [
        {
          name: 'Security Score',
          type: 'pie',
          radius: ['40%', '70%'],
          avoidLabelOverlap: false,
          itemStyle: {
            borderRadius: 10,
            borderColor: theme === 'dark' ? '#1F2937' : '#FFFFFF',
            borderWidth: 2
          },
          label: {
            show: false,
            position: 'center'
          },
          emphasis: {
            label: {
              show: true,
              fontSize: '20',
              fontWeight: 'bold',
              formatter: '{b}\n{d}%'
            }
          },
          labelLine: {
            show: false
          },
          data: [
            {
              value: 85,
              name: 'Compliant',
              itemStyle: { color: '#10B981' }
            },
            {
              value: 10,
              name: 'At Risk',
              itemStyle: { color: '#F59E0B' }
            },
            {
              value: 5,
              name: 'Critical',
              itemStyle: { color: '#EF4444' }
            }
          ]
        }
      ]
    }
    
    chart.setOption(option)
    
    const handleResize = () => {
      chart.resize()
    }
    
    window.addEventListener('resize', handleResize)
    
    return () => {
      chart.dispose()
      window.removeEventListener('resize', handleResize)
    }
  }, [theme])
  
  return (
    <div className="space-y-4">
      <div
        ref={chartRef}
        className="h-64 w-full"
      />
      
      {/* Score Details */}
      <div className="grid grid-cols-3 gap-4">
        <div>
          <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">
            Network Security
          </h4>
          <p className="mt-1 text-lg font-semibold text-gray-900 dark:text-white">
            90%
          </p>
        </div>
        <div>
          <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">
            Endpoint Security
          </h4>
          <p className="mt-1 text-lg font-semibold text-gray-900 dark:text-white">
            82%
          </p>
        </div>
        <div>
          <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400">
            Cloud Security
          </h4>
          <p className="mt-1 text-lg font-semibold text-gray-900 dark:text-white">
            88%
          </p>
        </div>
      </div>
    </div>
  )
} 