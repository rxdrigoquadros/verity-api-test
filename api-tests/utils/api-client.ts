import { APIRequestContext } from '@playwright/test';

export class ApiClient {
  constructor(private request: APIRequestContext) {}

  async authenticate(email: string, password: string): Promise<string> {
    const response = await this.request.post('/login', {
      data: { email, password }
    });
    const body = await response.json();
    return body.authorization;
  }

  async createUser(userData: any, token?: string) {
    const headers = token ? { Authorization: token } : {};
    return await this.request.post('/usuarios', {
      data: userData,
      headers
    });
  }
  
  // ... outros métodos
}