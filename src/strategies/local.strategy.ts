import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from 'src/auth/auth.service';
import { LoginDto } from 'src/dto/login.dto';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super();
  }

  validate(loginDto: LoginDto) {
    const user = this.authService.login(loginDto);
    if (!user) new UnauthorizedException('Invalid Credentials');
    return user;
  }
}
