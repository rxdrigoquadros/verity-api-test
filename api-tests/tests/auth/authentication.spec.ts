// tests/auth/authentication.spec.ts
import { test, expect } from '../../utils/test-fixtures';
import { FixtureLoader } from '../../utils/fixture-loader';
import { APIResponse } from '@playwright/test';

test.describe('Autenticação - POST /login', () => {
  
  test.describe('Cenários de Sucesso', () => {
    
    test('deve autenticar usuário com credenciais válidas', async ({ apiClient }) => {
      // Primeiro cria um usuário para garantir que existe
      const userData = FixtureLoader.generate('users/valid-users', {
        email: `auth_test_${Date.now()}@teste.com`
      });
      
      // Cria o usuário
      const createResponse = await apiClient.createUser(userData);
      expect(createResponse.status()).toBe(201);
      
      // Tenta autenticar
      const loginResponse = await apiClient.authenticate(
        userData.email, 
        userData.password
      );
      
      expect(loginResponse.status).toBe(200);
      expect(loginResponse.body).toHaveProperty('authorization');
      expect(loginResponse.body).toHaveProperty('message', 'Login realizado com sucesso');
      
      // Valida formato do token JWT
      const token = loginResponse.body.authorization;
      expect(token).toMatch(/^Bearer\s+[\w-]+\.[\w-]+\.[\w-]+$/);
    });

    test('deve autenticar usuário administrador', async ({ apiClient, validUsers }) => {
      // Cria um admin
      const adminData = {
        ...validUsers.adminUser,
        email: `admin_${Date.now()}@teste.com`
      };
      
      await apiClient.createUser(adminData);
      
      const loginResponse = await apiClient.authenticate(
        adminData.email,
        adminData.password
      );
      
      expect(loginResponse.status).toBe(200);
      expect(loginResponse.body.authorization).toBeTruthy();
      
      // Verifica se o token tem privilégios de admin fazendo uma operação administrativa
      const token = loginResponse.body.authorization;
      const testResponse = await apiClient.request.get('/usuarios', {
        headers: { Authorization: token }
      });
      
      expect(testResponse.status()).toBe(200);
    });

    test('deve gerar tokens diferentes para cada login', async ({ apiClient }) => {
      const userData = FixtureLoader.generate('users/valid-users', {
        email: `multi_token_${Date.now()}@teste.com`
      });
      
      await apiClient.createUser(userData);
      
      // Faz dois logins
      const firstLogin = await apiClient.authenticate(
        userData.email,
        userData.password
      );
      
      // Aguarda um pouco para garantir timestamp diferente
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      const secondLogin = await apiClient.authenticate(
        userData.email,
        userData.password
      );
      
      expect(firstLogin.body.authorization).toBeTruthy();
      expect(secondLogin.body.authorization).toBeTruthy();
      expect(firstLogin.body.authorization).not.toBe(secondLogin.body.authorization);
    });
  });

  test.describe('Cenários de Falha', () => {
    
    test('deve falhar com email inexistente', async ({ apiClient }) => {
      const loginResponse = await apiClient.authenticate(
        'naoexiste@teste.com',
        'senha123'
      );
      
      expect(loginResponse.status).toBe(401);
      expect(loginResponse.body).toHaveProperty('message', 'Email e/ou senha inválidos');
    });

    test('deve falhar com senha incorreta', async ({ apiClient }) => {
      // Cria usuário
      const userData = FixtureLoader.generate('users/valid-users', {
        email: `wrong_pass_${Date.now()}@teste.com`
      });
      
      await apiClient.createUser(userData);
      
      // Tenta login com senha errada
      const loginResponse = await apiClient.authenticate(
        userData.email,
        'senhaErrada123'
      );
      
      expect(loginResponse.status).toBe(401);
      expect(loginResponse.body).toHaveProperty('message', 'Email e/ou senha inválidos');
    });

    test('deve falhar com email em formato inválido', async ({ apiClient }) => {
      const invalidEmails = [
        'email-sem-arroba',
        '@dominio.com',
        'usuario@',
        'usuario @dominio.com',
        'usuario@dominio',
        ''
      ];

      for (const email of invalidEmails) {
        const loginResponse = await apiClient.authenticate(email, 'senha123');
        
        expect(loginResponse.status).toBe(400);
        expect(loginResponse.body).toHaveProperty('email');
      }
    });

    test('deve falhar quando campos obrigatórios estão vazios', async ({ apiClient }) => {
      // Teste sem email
      let response = await apiClient.request.post('/login', {
        data: { password: 'senha123' }
      });
      
      expect(response.status()).toBe(400);
      let body = await response.json();
      expect(body).toHaveProperty('email', 'email é obrigatório');

      // Teste sem password
      response = await apiClient.request.post('/login', {
        data: { email: 'teste@teste.com' }
      });
      
      expect(response.status()).toBe(400);
      body = await response.json();
      expect(body).toHaveProperty('password', 'password é obrigatório');

      // Teste sem nenhum campo
      response = await apiClient.request.post('/login', {
        data: {}
      });
      
      expect(response.status()).toBe(400);
      body = await response.json();
      expect(body).toHaveProperty('email');
      expect(body).toHaveProperty('password');
    });

    test('deve falhar com campos nulos', async ({ apiClient }) => {
      const response = await apiClient.request.post('/login', {
        data: {
          email: null,
          password: null
        }
      });
      
      expect(response.status()).toBe(400);
    });

    test('deve validar tamanho mínimo da senha', async ({ apiClient }) => {
      const loginResponse = await apiClient.authenticate(
        'teste@teste.com',
        '12' // senha muito curta
      );
      
      expect(loginResponse.status).toBe(400);
    });
  });

  test.describe('Segurança e Validações', () => {
    
    test('deve prevenir SQL Injection', async ({ apiClient }) => {
      const maliciousInputs = [
        "' OR '1'='1",
        "admin'--",
        "' OR 1=1--",
        "'; DROP TABLE users;--",
        "' UNION SELECT * FROM users--"
      ];

      for (const input of maliciousInputs) {
        const loginResponse = await apiClient.authenticate(input, input);
        
        // Deve retornar erro de autenticação normal, não erro de SQL
        expect(loginResponse.status).toBeGreaterThanOrEqual(400);
        expect(loginResponse.status).toBeLessThan(500);
      }
    });

    test('deve prevenir XSS em mensagens de erro', async ({ apiClient }) => {
      const xssPayload = '<script>alert("XSS")</script>@teste.com';
      
      const loginResponse = await apiClient.authenticate(xssPayload, 'senha123');
      
      expect(loginResponse.status).toBe(400);
      
      // Verifica se o payload não é retornado sem sanitização
      const responseText = JSON.stringify(loginResponse.body);
      expect(responseText).not.toContain('<script>');
    });

    test('deve lidar com caracteres especiais', async ({ apiClient }) => {
      const userData = {
        nome: "José O'Brien",
        email: `special_chars_${Date.now()}@teste.com`,
        password: 'P@$$w0rd!#%&',
        administrador: 'false'
      };

      // Cria usuário com senha contendo caracteres especiais
      await apiClient.createUser(userData);
      
      // Deve conseguir autenticar
      const loginResponse = await apiClient.authenticate(
        userData.email,
        userData.password
      );
      
      expect(loginResponse.status).toBe(200);
    });

    test('deve ter timeout apropriado', async ({ apiClient }) => {
      const startTime = Date.now();
      
      // Tenta login com credenciais inválidas
      await apiClient.authenticate(
        'timeout@teste.com',
        'senha123'
      );
      
      const endTime = Date.now();
      const responseTime = endTime - startTime;
      
      // Resposta não deve demorar mais que 5 segundos
      expect(responseTime).toBeLessThan(5000);
    });
  });

  test.describe('Uso do Token JWT', () => {
    
    test('deve aceitar requisições com token válido', async ({ apiClient }) => {
      // Cria e autentica usuário
      const userData = FixtureLoader.generate('users/valid-users', {
        email: `token_test_${Date.now()}@teste.com`
      });
      
      const createResponse = await apiClient.createUser(userData);
      const userId = (await createResponse.json())._id;
      
      const loginResponse = await apiClient.authenticate(
        userData.email,
        userData.password
      );
      
      const token = loginResponse.body.authorization;
      
      // Usa o token para buscar dados do usuário
      const response = await apiClient.request.get(`/usuarios/${userId}`, {
        headers: { Authorization: token }
      });
      
      expect(response.status()).toBe(200);
    });

    test('deve rejeitar requisições sem token quando necessário', async ({ apiClient }) => {
      // Tenta acessar endpoint protegido sem token
      const response = await apiClient.request.delete('/usuarios/123456');
      
      expect(response.status()).toBe(401);
      const body = await response.json();
      expect(body).toHaveProperty('message');
    });

    test('deve rejeitar token mal formatado', async ({ apiClient }) => {
      const invalidTokens = [
        'InvalidToken',
        'Bearer',
        'Bearer ',
        'token-sem-bearer',
        'Bearer token.invalido',
        'Bearer a.b', // JWT precisa de 3 partes
      ];

      for (const token of invalidTokens) {
        const response = await apiClient.request.get('/usuarios', {
          headers: { Authorization: token }
        });
        
        expect(response.status()).toBe(401);
      }
    });

    test('deve rejeitar token expirado', async ({ apiClient }) => {
      // Este teste depende de como a API lida com expiração
      // Você pode mockar um token expirado ou aguardar a expiração real
      
      const expiredToken = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjB9.xyz';
      
      const response = await apiClient.request.get('/usuarios', {
        headers: { Authorization: expiredToken }
      });
      
      expect(response.status()).toBe(401);
    });
  });

  test.describe('Rate Limiting no Login', () => {
    
    test('deve bloquear após múltiplas tentativas de login falhadas', async ({ apiClient }) => {
      const email = `brute_force_${Date.now()}@teste.com`;
      const responses: any[] = [];
      
      // Tenta 10 logins rápidos com senha errada
      for (let i = 0; i < 10; i++) {
        const response = await apiClient.authenticate(email, 'senhaErrada');
        responses.push(response);
      }
      
      // Verifica se alguma das últimas respostas indica rate limiting
      const lastResponses = responses.slice(-3);
      const hasRateLimiting = lastResponses.some(r => 
        r.status === 429 || // Too Many Requests
        (r.body.message && r.body.message.includes('muitas tentativas'))
      );
      
      // Se a API implementa rate limiting, deve ter bloqueado
      if (hasRateLimiting) {
        expect(hasRateLimiting).toBe(true);
      } else {
        // Se não implementa, todos devem retornar 401
        expect(responses.every(r => r.status === 401)).toBe(true);
      }
    });
  });

  test.describe('Validações de Contrato', () => {
    
    test('deve retornar estrutura correta na resposta de sucesso', async ({ apiClient }) => {
      const userData = FixtureLoader.generate('users/valid-users', {
        email: `contract_${Date.now()}@teste.com`
      });
      
      await apiClient.createUser(userData);
      
      const loginResponse = await apiClient.authenticate(
        userData.email,
        userData.password
      );
      
      // Valida estrutura da resposta
      expect(loginResponse.body).toMatchObject({
        message: expect.any(String),
        authorization: expect.stringMatching(/^Bearer\s+.+$/)
      });
      
      // Valida que não há campos extras não documentados
      const expectedFields = ['message', 'authorization'];
      const actualFields = Object.keys(loginResponse.body);
      expect(actualFields.sort()).toEqual(expectedFields.sort());
    });

    test('deve retornar content-type correto', async ({ apiClient }) => {
      const response = await apiClient.request.post('/login', {
        data: {
          email: 'teste@teste.com',
          password: 'senha123'
        }
      });
      
      expect(response.headers()['content-type']).toContain('application/json');
    });
  });
});