import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import jwt from 'jsonwebtoken'

type JwtPayload = {
  id: number
  email: string
  role: string
}

export function middleware(request: NextRequest) {
  const authHeader = request.headers.get('authorization')

  if (!authHeader) {
    return NextResponse.json(
      {
        error: 'Unauthorized - Token tidak ada'
      },
      {
        status: 401
      }
    )
  }

  try {
    const token = authHeader.replace('Bearer ', '')

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET!
    ) as JwtPayload

    const pathname = request.nextUrl.pathname

    if (pathname.startsWith('/api/purchase-order')) {
      if (
        decoded.role !== 'vendor' &&
        decoded.role !== 'admin_inbound'
      ) {
        return NextResponse.json(
          {
            error: 'Forbidden'
          },
          {
            status: 403
          }
        )
      }
    }

    if (pathname.startsWith('/api/delivery-order')) {
      if (decoded.role !== 'vendor') {
        return NextResponse.json(
          {
            error: 'Forbidden'
          },
          {
            status: 403
          }
        )
      }
    }

    if (pathname.startsWith('/api/inbound-scan')) {
      if (decoded.role !== 'admin_inbound') {
        return NextResponse.json(
          {
            error: 'Forbidden'
          },
          {
            status: 403
          }
        )
      }
    }

    if (pathname.startsWith('/api/discrepancy-ticket')) {
      if (
        decoded.role !== 'supervisor_qc' &&
        decoded.role !== 'engineering_iqc'
      ) {
        return NextResponse.json(
          {
            error: 'Forbidden'
          },
          {
            status: 403
          }
        )
      }
    }

    if (pathname.startsWith('/api/inventory-record')) {
      if (decoded.role !== 'admin_inbound') {
        return NextResponse.json(
          {
            error: 'Forbidden'
          },
          {
            status: 403
          }
        )
      }
    }

    if (pathname.startsWith('/api/audit-log')) {
      if (decoded.role !== 'supervisor_qc') {
        return NextResponse.json(
          {
            error: 'Forbidden'
          },
          {
            status: 403
          }
        )
      }
    }

    return NextResponse.next()
  } catch (error) {
    return NextResponse.json(
      {
        error: 'Unauthorized - Token invalid'
      },
      {
        status: 401
      }
    )
  }
}

export const config = {
  matcher: [
    '/api/purchase-order/:path*',
    '/api/delivery-order/:path*',
    '/api/inbound-scan/:path*',
    '/api/discrepancy-ticket/:path*',
    '/api/inventory-record/:path*',
    '/api/audit-log/:path*'
  ]
}