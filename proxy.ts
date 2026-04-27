import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import jwt from 'jsonwebtoken'

type JwtPayload = {
  id: number
  email: string
  role: string
}

export function proxy(request: NextRequest) {
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

    if (pathname.startsWith('/api/vendor')) {
      if (
        decoded.role !== 'admin_inbound' &&
        decoded.role !== 'supervisor_qc'
      ) {
        return NextResponse.json(
          { error: 'Forbidden' },
          { status: 403 }
        )
      }
    }

    if (pathname.startsWith('/api/item')) {
      if (
        decoded.role !== 'admin_inbound' &&
        decoded.role !== 'vendor' &&
        decoded.role !== 'supervisor_qc' &&
        decoded.role !== 'engineering_iqc'
      ) {
        return NextResponse.json(
          { error: 'Forbidden' },
          { status: 403 }
        )
      }
    }

    if (pathname.startsWith('/api/purchase-order')) {
      if (
        decoded.role !== 'vendor' &&
        decoded.role !== 'admin_inbound'
      ) {
        return NextResponse.json(
          { error: 'Forbidden' },
          { status: 403 }
        )
      }
    }

    if (pathname.startsWith('/api/delivery-order')) {
      if (
        decoded.role !== 'vendor' &&
        decoded.role !== 'admin_inbound'
      ) {
        return NextResponse.json(
          { error: 'Forbidden' },
          { status: 403 }
        )
      }
    }

    if (pathname.startsWith('/api/inbound-scan')) {
      if (decoded.role !== 'admin_inbound') {
        return NextResponse.json(
          { error: 'Forbidden' },
          { status: 403 }
        )
      }
    }

    if (pathname.startsWith('/api/geo-tag')) {
      if (decoded.role !== 'admin_inbound') {
        return NextResponse.json(
          { error: 'Forbidden' },
          { status: 403 }
        )
      }
    }

    if (pathname.startsWith('/api/photo-evidence')) {
      if (
        decoded.role !== 'admin_inbound' &&
        decoded.role !== 'engineering_iqc'
      ) {
        return NextResponse.json(
          { error: 'Forbidden' },
          { status: 403 }
        )
      }
    }

    if (pathname.startsWith('/api/discrepancy-ticket')) {
      if (
        decoded.role !== 'supervisor_qc' &&
        decoded.role !== 'engineering_iqc'
      ) {
        return NextResponse.json(
          { error: 'Forbidden' },
          { status: 403 }
        )
      }
    }

    if (pathname.startsWith('/api/inventory-record')) {
      if (decoded.role !== 'admin_inbound') {
        return NextResponse.json(
          { error: 'Forbidden' },
          { status: 403 }
        )
      }
    }

    if (pathname.startsWith('/api/audit-log')) {
      if (decoded.role !== 'supervisor_qc') {
        return NextResponse.json(
          { error: 'Forbidden' },
          { status: 403 }
        )
      }
    }

    return NextResponse.next()
  } catch (error) {
    const jwtError =
      error instanceof Error ? error.message : 'Unknown JWT error'

    console.error('JWT verification failed', {
      pathname: request.nextUrl.pathname,
      authHeader,
      jwtError
    })

    return NextResponse.json(
      {
        error: 'Unauthorized - Token invalid',
        details: jwtError
      },
      {
        status: 401
      }
    )
  }
}

export const config = {
  matcher: [
    '/api/vendor/:path*',
    '/api/item/:path*',
    '/api/purchase-order/:path*',
    '/api/delivery-order/:path*',
    '/api/inbound-scan/:path*',
    '/api/geo-tag/:path*',
    '/api/photo-evidence/:path*',
    '/api/discrepancy-ticket/:path*',
    '/api/inventory-record/:path*',
    '/api/audit-log/:path*'
  ]
}