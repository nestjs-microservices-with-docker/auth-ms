import { Injectable } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { LoginUserDto, RegisterUserDto } from './dto';
import { JwtService } from '@nestjs/jwt';
import { JwtAuthPayload } from './interfaces';
import { envs } from 'src/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async registerUser(registerUserDto: RegisterUserDto) {
    const { email, username, password } = registerUserDto;
    try {
      const userFound = await this.prisma.user.findUnique({
        where: {
          email,
        },
      });

      if (userFound) {
        throw new RpcException({
          status: 409,
          message: 'User already exists',
        });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const user = await this.prisma.user.create({
        data: {
          email,
          username,
          password: hashedPassword,
        },
      });

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: _, ...userWithoutPassword } = user;

      return userWithoutPassword;
    } catch (error) {
      const err = error as Error;
      throw new RpcException({
        status: 500,
        message: err.message,
      });
    }
  }

  async signJwt(payload: JwtAuthPayload) {
    return this.jwtService.signAsync(
      {
        payload,
      },
      {
        secret: envs.jwtSecret,
        expiresIn: '2h',
      },
    );
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;

    try {
      const userFound = await this.prisma.user.findUnique({
        where: {
          email,
        },
      });

      if (!userFound) {
        throw new RpcException({
          status: 404,
          message: 'Invalid credentials',
        });
      }

      const isPasswordValid = await bcrypt.compare(
        password,
        userFound.password,
      );

      if (!isPasswordValid) {
        throw new RpcException({
          status: 404,
          message: 'Invalid credentials',
        });
      }

      const token = await this.signJwt({
        id: userFound.id,
        email: userFound.email,
        username: userFound.username,
      });

      return {
        id: userFound.id,
        email: userFound.email,
        username: userFound.username,
        token,
      };
    } catch (error) {
      const err = error as Error;

      throw new RpcException({
        status: 500,
        message: err.message,
      });
    }
  }

  async verifyToken(token: string) {
    try {
      const user: JwtAuthPayload = await this.jwtService.verifyAsync(token, {
        secret: envs.jwtSecret,
      });
      const validatedToken = await this.signJwt(user);

      console.log('Verify token');
      console.log({ ...user, validatedToken });

      return {
        user: { ...user },
        token: validatedToken,
      };
    } catch (error) {
      const err = error as Error;

      throw new RpcException({
        status: 401,
        message: err.message,
      });
    }
  }
}
