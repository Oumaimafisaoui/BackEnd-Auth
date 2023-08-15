import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthDto } from './dto/index';
import { AuthService } from './auth.service';
import { GoogleAuthGuard } from './guard/google.guard';
import { GetUser } from '../auth/decorator';
import { User } from '@prisma/client';
@Controller('auth') //what request it handles
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  register(@Body() dto: AuthDto) {
    return this.authService.register(dto);
  }
  @HttpCode(HttpStatus.OK)
  @Post('login')
  login(@Body() dto: AuthDto) {
    return this.authService.login(dto);
  }

  @Get('google/login')
  @UseGuards(GoogleAuthGuard)
  handlelogin() {
    return 'login';
  }

  @Get('google/redirect')
  @UseGuards(GoogleAuthGuard)
  handleRedirect(@Req() req: Request) {
    // console.log(req)
    // console.log(req);
    // console.log(req);
    return this.authService.loginGoogle(req);
  }
  @Get('42/login')
  handlefourtyLogin() {}

  @Get('42/redirect')
  handlefourtyRedirect() {}
}
