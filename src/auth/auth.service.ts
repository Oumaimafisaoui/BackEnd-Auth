import { ForbiddenException, Injectable } from '@nestjs/common';
import { AuthDto } from 'src/dto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { waitForDebugger } from 'inspector';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
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
      delete user.hash; //transformer
      return user;
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
}
