import { NextResponse } from 'next/server'
import { supabase } from '../../../../lib/supabase'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

export async function POST(req: Request) {
  try {
    const body = await req.json()

    const { email, password } = body

    if (!email || !password) {
      return NextResponse.json(
        {
          error: 'Email dan password wajib diisi'
        },
        {
          status: 400
        }
      )
    }

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single()

    if (error || !user) {
      return NextResponse.json(
        {
          error: 'User tidak ditemukan'
        },
        {
          status: 404
        }
      )
    }

    const isValidPassword = await bcrypt.compare(
      password,
      user.password_hash
    )

    if (!isValidPassword) {
      return NextResponse.json(
        {
          error: 'Password salah'
        },
        {
          status: 401
        }
      )
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role
      },
      process.env.JWT_SECRET!,
      {
        expiresIn: '1d'
      }
    )

    await supabase
      .from('users')
      .update({
        last_login: new Date()
      })
      .eq('id', user.id)

    return NextResponse.json({
      message: 'Login berhasil',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    })
  } catch (error) {
    return NextResponse.json(
      {
        error: 'Terjadi kesalahan pada server'
      },
      {
        status: 500
      }
    )
  }
}