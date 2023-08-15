import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Profile } from 'passport';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthService } from '../auth.service';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    config: ConfigService,
    private prisma: PrismaService,
    private auth: AuthService,
  ) {
    super({
      clientID: config.get('GOOGLE_ID'),
      clientSecret: config.get('CLIENT_SECRET'),
      callbackURL: config.get('CALLBACK'),
      scope: ['profile', 'email'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    // console.log("enter");
    const { emails } = profile;
    // console.log(profile);
    const user = {
      email: emails[0].value,
      accessToken,
    };
    done(null, user);
    // return user;
  }
}
