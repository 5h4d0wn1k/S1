import { useEffect, useRef } from 'react'
import * as echarts from 'echarts'
import { useTheme } from 'next-themes'

export function AlertsChart() {
  const chartRef = useRef<HTMLDivElement>(null)
  const { theme } = useTheme()
  
  useEffect(() => {
    if (!chartRef.current) return
    
    const chart = echarts.init(chartRef.current, theme)
    
    const option = {
      tooltip: {
        trigger: 'axis',
        axisPointer: {
          type: 'shadow'
        }
      },
      grid: {
        left: '3%',
        right: '4%',
        bottom: '3%',
        containLabel: true
      },
      xAxis: {
        type: 'category',
        data: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
        axisLine: {
          lineStyle: {
            color: theme === 'dark' ? '#4B5563' : '#E5E7EB'
          }
        },
        axisLabel: {
          color: theme === 'dark' ? '#9CA3AF' : '#4B5563'
        }
      },
      yAxis: {
        type: 'value',
        splitLine: {
          lineStyle: {
            color: theme === 'dark' ? '#374151' : '#F3F4F6'
          }
        },
        axisLabel: {
          color: theme === 'dark' ? '#9CA3AF' : '#4B5563'
        }
      },
      series: [
        {
          name: 'Critical',
          type: 'bar',
          stack: 'total',
          data: [5, 3, 7, 4, 2, 1, 3],
          itemStyle: {
            color: '#EF4444'
          }
        },
        {
          name: 'High',
          type: 'bar',
          stack: 'total',
          data: [8, 12, 10, 15, 7, 5, 9],
          itemStyle: {
            color: '#F59E0B'
          }
        },
        {
          name: 'Medium',
          type: 'bar',
          stack: 'total',
          data: [15, 18, 13, 20, 12, 8, 14],
          itemStyle: {
            color: '#3B82F6'
          }
        },
        {
          name: 'Low',
          type: 'bar',
          stack: 'total',
          data: [25, 22, 19, 28, 17, 12, 20],
          itemStyle: {
            color: '#10B981'
          }
        }
      ],
      legend: {
        data: ['Critical', 'High', 'Medium', 'Low'],
        top: 'bottom',
        textStyle: {
          color: theme === 'dark' ? '#9CA3AF' : '#4B5563'
        }
      }
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
    <div
      ref={chartRef}
      className="h-64 w-full"
    />
  )
} 