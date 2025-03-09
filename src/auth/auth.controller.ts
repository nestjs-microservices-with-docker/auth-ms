import { Controller } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { LoginUserDto, RegisterUserDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @MessagePattern({ cmd: 'auth.register.user' })
  register(@Payload() registerUserDto: RegisterUserDto) {
    return this.authService.registerUser(registerUserDto);
  }

  @MessagePattern({ cmd: 'auth.login.user' })
  login(@Payload() loginUserDto: LoginUserDto) {
    return this.authService.loginUser(loginUserDto);
  }

  @MessagePattern({ cmd: 'auth.verify.token' })
  verify(@Payload() token: string) {
    return this.authService.verifyToken(token);
  }
}
