import { ForbiddenException, Injectable } from '@nestjs/common';
import { AuthDto } from 'src/dto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { userInfo } from 'os';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private conf: ConfigService,
  ) {}
  async signin(dto: AuthDto) {
    //find user by email
    // if user does not exist throw exception
    //compare passwords
    //if password is incorrect thew an exep
    //if all good send back the user
    const target = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!target) {
      throw new ForbiddenException('User not found');
    }
    const pwMatch = await argon.verify(target.hash, dto.password);
    if (!pwMatch) {
      throw new ForbiddenException('Incorrect password');
    }
    return this.signToken(target.id, target.email);
  }

  async signup(dto: AuthDto) {
    //generate the password
    //save the new user in db
    //return the saved user
    const hash = await argon.hash(dto.password);
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });
      return this.signToken(user.id, user.email);
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Cridentials taken!');
        }
      } else {
        throw error;
      }
    }
  }

  signToken(userId: number, email: string) : Promise<string> {
    //1 - sign the token aka validate it

    //data encoded insode the jwt
    const payload = {
      sub: userId,
      email,
    };
    const secret = this.conf.get("JWT_SEC");

    return this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: secret,
    });
  }
}
