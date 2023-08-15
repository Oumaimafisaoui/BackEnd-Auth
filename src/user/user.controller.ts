import { Controller, Get, Patch, UseGuards } from '@nestjs/common';
import { GetUser } from '../auth/decorator';
import { JwtGuard } from 'src/auth/guard';
import { User } from '@prisma/client';

@Controller('users')
export class UserController {
  @UseGuards(JwtGuard)
  @Get('me')
  getMe(@GetUser() user: User, @GetUser('email') email: string) {
    console.log(email);
    return user;
  }

  // @Patch()
  // editProfile(){}
}
