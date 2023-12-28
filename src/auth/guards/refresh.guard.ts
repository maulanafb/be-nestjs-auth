import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';

@Injectable()
export class RefreshJwtGuard implements CanActivate {
  constructor(private jwtservice: JwtService) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFormHeader(request);
    console.log(request.headers.authorization);
    if (!token) throw new UnauthorizedException('jirrlah');
    try {
      const payload = await this.jwtservice.verifyAsync(token, {
        secret: process.env.jwtrefreshTokenKey,
      });

      request['user'] = payload;
    } catch (err) {
      throw new UnauthorizedException('jir');
    }
    return true;
  }

  private extractTokenFormHeader(request: Request) {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];

    return type === 'Refresh' ? token : undefined;
  }
}
