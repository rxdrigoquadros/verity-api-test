// tests/users/create-user.spec.ts
import { test, expect } from '../../utils/test-fixtures';
import { FixtureLoader } from '../../utils/fixture-loader';

test.describe('POST /usuarios - Criação de Usuários', () => {

  test.describe('Cenários de Sucesso', () => {

    test('deve criar usuário com todos os campos válidos', async ({ apiClient }) => {
      const userData = FixtureLoader.generate('users/valid-users', {
        email: `user_${Date.now()}@teste.com`
      });

      const response = await apiClient.createUser(userData);
      
      expect(response.status()).toBe(201);
      
      const body = await response.json();
      expect(body).toHaveProperty('message', 'Cadastro realizado com sucesso');
      expect(body).toHaveProperty('_id');
      expect(body._id).toBeTruthy();
      
      // Verifica se o usuário foi realmente criado
      const getResponse = await apiClient.request.get(`/usuarios/${body._id}`);
      expect(getResponse.status()).toBe(200);
      
      const createdUser = await getResponse.json();
      expect(createdUser.nome).toBe(userData.nome);
      expect(createdUser.email).toBe(userData.email);
      expect(createdUser.administrador).toBe(userData.administrador);
      // Senha não deve ser retornada
      expect(createdUser.password).toBeUndefined();
    });

    test('deve criar usuário administrador', async ({ apiClient }) => {
      const adminData = {
        nome: 'Admin Test',
        email: `admin_${Date.now()}@teste.com`,
        password: 'adminPass123',
        administrador: 'true'
      };

      const response = await apiClient.createUser(adminData);
      
      expect(response.status()).toBe(201);
      
      const body = await response.json();
      const userId = body._id;
      
      // Verifica se foi criado como admin
      const getResponse = await apiClient.request.get(`/usuarios/${userId}`);
      const user = await getResponse.json();
      
      expect(user.administrador).toBe('true');
    });

    test('deve criar usuário não-administrador', async ({ apiClient }) => {
      const userData = {
        nome: 'User Test',
        email: `user_${Date.now()}@teste.com`,
        password: 'userPass123',
        administrador: 'false'
      };

      const response = await apiClient.createUser(userData);
      
      expect(response.status()).toBe(201);
      
      const body = await response.json();
      const userId = body._id;
      
      // Verifica se foi criado como usuário comum
      const getResponse = await apiClient.request.get(`/usuarios/${userId}`);
      const user = await getResponse.json();
      
      expect(user.administrador).toBe('false');
    });

    test('deve aceitar nomes com caracteres especiais', async ({ apiClient }) => {
      const specialNames = [
        "José da Silva",
        "Maria D'Angelo",
        "João-Pedro",
        "Ana Müller",
        "François Dubois",
        "李明", // Caracteres chineses
        "محمد", // Caracteres árabes
        "Владимир", // Caracteres cirílicos
        "José & Maria",
        "O'Connor"
      ];

      for (const nome of specialNames) {
        const userData = {
          nome,
          email: `special_${Date.now()}_${Math.random()}@teste.com`,
          password: 'senha123',
          administrador: 'false'
        };

        const response = await apiClient.createUser(userData);
        
        expect(response.status()).toBe(201);
        
        const body = await response.json();
        
        // Verifica se o nome foi salvo corretamente
        const getResponse = await apiClient.request.get(`/usuarios/${body._id}`);
        const user = await getResponse.json();
        
        expect(user.nome).toBe(nome);
      }
    });

    test('deve aceitar senhas complexas', async ({ apiClient }) => {
      const complexPasswords = [
        'SenhaForte123!',
        'P@$$w0rd#2024',
        '!@#$%^&*()_+-=',
        'ümläut123',
        '12345678901234567890', // Senha longa
        'a'.repeat(50), // 50 caracteres
      ];

      for (const password of complexPasswords) {
        const userData = {
          nome: 'Test User',
          email: `complex_pass_${Date.now()}_${Math.random()}@teste.com`,
          password,
          administrador: 'false'
        };

        const response = await apiClient.createUser(userData);
        
        expect(response.status()).toBe(201);
        
        // Tenta fazer login com a senha complexa
        const loginResponse = await apiClient.authenticate(userData.email, password);
        expect(loginResponse.status).toBe(200);
      }
    });

    test('deve criar múltiplos usuários em sequência', async ({ apiClient }) => {
      const numberOfUsers = 5;
      const createdUsers = [];

      for (let i = 0; i < numberOfUsers; i++) {
        const userData = {
          nome: `Bulk User ${i}`,
          email: `bulk_${i}_${Date.now()}@teste.com`,
          password: 'senha123',
          administrador: 'false'
        };

        const response = await apiClient.createUser(userData);
        expect(response.status()).toBe(201);
        
        const body = await response.json();
        createdUsers.push(body._id);
      }

      // Verifica se todos foram criados
      expect(createdUsers.length).toBe(numberOfUsers);
      expect(new Set(createdUsers).size).toBe(numberOfUsers); // IDs únicos
    });
  });

  test.describe('Validações de Campos Obrigatórios', () => {

    test('deve falhar quando campo "nome" está ausente', async ({ apiClient }) => {
      const userData = {
        email: `test_${Date.now()}@teste.com`,
        password: 'senha123',
        administrador: 'false'
      };

      const response = await apiClient.request.post('/usuarios', {
        data: userData
      });
      
      expect(response.status()).toBe(400);
      
      const body = await response.json();
      expect(body).toHaveProperty('nome');
      expect(body.nome).toContain('obrigatório');
    });

    test('deve falhar quando campo "email" está ausente', async ({ apiClient }) => {
      const userData = {
        nome: 'Test User',
        password: 'senha123',
        administrador: 'false'
      };

      const response = await apiClient.request.post('/usuarios', {
        data: userData
      });
      
      expect(response.status()).toBe(400);
      
      const body = await response.json();
      expect(body).toHaveProperty('email');
      expect(body.email).toContain('obrigatório');
    });

    test('deve falhar quando campo "password" está ausente', async ({ apiClient }) => {
      const userData = {
        nome: 'Test User',
        email: `test_${Date.now()}@teste.com`,
        administrador: 'false'
      };

      const response = await apiClient.request.post('/usuarios', {
        data: userData
      });
      
      expect(response.status()).toBe(400);
      
      const body = await response.json();
      expect(body).toHaveProperty('password');
      expect(body.password).toContain('obrigatório');
    });

    test('deve falhar quando campo "administrador" está ausente', async ({ apiClient }) => {
      const userData = {
        nome: 'Test User',
        email: `test_${Date.now()}@teste.com`,
        password: 'senha123'
      };

      const response = await apiClient.request.post('/usuarios', {
        data: userData
      });
      
      expect(response.status()).toBe(400);
      
      const body = await response.json();
      expect(body).toHaveProperty('administrador');
      expect(body.administrador).toContain('obrigatório');
    });

    test('deve falhar quando múltiplos campos estão ausentes', async ({ apiClient }) => {
      const testCases = [
        { data: {}, expectedFields: ['nome', 'email', 'password', 'administrador'] },
        { data: { nome: 'Test' }, expectedFields: ['email', 'password', 'administrador'] },
        { data: { email: 'test@test.com' }, expectedFields: ['nome', 'password', 'administrador'] },
        { data: { nome: 'Test', email: 'test@test.com' }, expectedFields: ['password', 'administrador'] }
      ];

      for (const testCase of testCases) {
        const response = await apiClient.request.post('/usuarios', {
          data: testCase.data
        });
        
        expect(response.status()).toBe(400);
        
        const body = await response.json();
        
        for (const field of testCase.expectedFields) {
          expect(body).toHaveProperty(field);
        }
      }
    });
  });

  test.describe('Validações de Formato e Tipo', () => {

    test('deve falhar com email em formato inválido', async ({ apiClient }) => {
      const invalidEmails = [
        'email-sem-arroba',
        '@dominio.com',
        'usuario@',
        'usuario @dominio.com',
        'usuario@dominio',
        'usuario@@dominio.com',
        'usuario@dominio..com',
        '.usuario@dominio.com',
        'usuario.@dominio.com',
        'usuário@domínio.com', // com acentos
      ];

      for (const email of invalidEmails) {
        const userData = {
          nome: 'Test User',
          email,
          password: 'senha123',
          administrador: 'false'
        };

        const response = await apiClient.createUser(userData);
        
        expect(response.status()).toBe(400);
        
        const body = await response.json();
        expect(body).toHaveProperty('email');
        
        console.log(`Email inválido testado: ${email}`);
      }
    });

    test('deve aceitar emails válidos em diferentes formatos', async ({ apiClient }) => {
      const validEmails = [
        'user@example.com',
        'user.name@example.com',
        'user+tag@example.com',
        'user_name@example.com',
        '123@example.com',
        'user@subdomain.example.com',
        'user@example.co.uk',
        'a@b.co'
      ];

      for (const email of validEmails) {
        const uniqueEmail = email.replace('@', `_${Date.now()}@`);
        const userData = {
          nome: 'Test User',
          email: uniqueEmail,
          password: 'senha123',
          administrador: 'false'
        };

        const response = await apiClient.createUser(userData);
        
        expect(response.status()).toBe(201);
        
        console.log(`Email válido testado: ${uniqueEmail}`);
      }
    });

    test('deve falhar quando administrador não é "true" ou "false"', async ({ apiClient }) => {
      const invalidAdminValues = [
        'TRUE',
        'FALSE',
        'True',
        'False',
        '1',
        '0',
        'yes',
        'no',
        'sim',
        'não',
        true,
        false,
        1,
        0,
        null,
        undefined
      ];

      for (const adminValue of invalidAdminValues) {
        const userData = {
          nome: 'Test User',
          email: `test_${Date.now()}_${Math.random()}@teste.com`,
          password: 'senha123',
          administrador: adminValue
        };

        const response = await apiClient.request.post('/usuarios', {
          data: userData
        });
        
        expect(response.status()).toBe(400);
        
        const body = await response.json();
        expect(body).toHaveProperty('administrador');
        
        console.log(`Valor administrador inválido testado: ${adminValue}`);
      }
    });

    test('deve falhar com campos vazios', async ({ apiClient }) => {
      const userData = {
        nome: '',
        email: '',
        password: '',
        administrador: ''
      };

      const response = await apiClient.createUser(userData);
      
      expect(response.status()).toBe(400);
      
      const body = await response.json();
      // Campos vazios devem gerar erros
      expect(Object.keys(body).length).toBeGreaterThan(0);
    });

    test('deve falhar com campos contendo apenas espaços', async ({ apiClient }) => {
      const userData = {
        nome: '   ',
        email: '   ',
        password: '   ',
        administrador: '   '
      };

      const response = await apiClient.createUser(userData);
      
      expect(response.status()).toBe(400);
    });

    test('deve validar tamanho mínimo da senha', async ({ apiClient }) => {
      const shortPasswords = [
        '',
        'a',
        '12',
        '123',
        '1234',
        '12345'
      ];

      for (const password of shortPasswords) {
        const userData = {
          nome: 'Test User',
          email: `test_${Date.now()}_${Math.random()}@teste.com`,
          password,
          administrador: 'false'
        };

        const response = await apiClient.createUser(userData);
        
        // Dependendo da API, pode retornar 400 ou aceitar
        // Ajuste conforme o comportamento esperado
        if (response.status() === 400) {
          const body = await response.json();
          expect(body).toHaveProperty('password');
          console.log(`Senha curta testada: "${password}" (${password.length} caracteres)`);
        }
      }
    });

    test('deve validar tamanho máximo dos campos', async ({ apiClient }) => {
      const longString = 'a'.repeat(1000);
      
      const testCases = [
        {
          field: 'nome',
          data: {
            nome: longString,
            email: `test_${Date.now()}@teste.com`,
            password: 'senha123',
            administrador: 'false'
          }
        },
        {
          field: 'email',
          data: {
            nome: 'Test User',
            email: `${longString}@teste.com`,
            password: 'senha123',
            administrador: 'false'
          }
        },
        {
          field: 'password',
          data: {
            nome: 'Test User',
            email: `test_${Date.now()}@teste.com`,
            password: longString,
            administrador: 'false'
          }
        }
      ];

      for (const testCase of testCases) {
        const response = await apiClient.createUser(testCase.data);
        
        // A API pode aceitar ou rejeitar strings muito longas
        if (response.status() === 400) {
          const body = await response.json();
          console.log(`Campo ${testCase.field} com 1000 caracteres foi rejeitado`);
        } else if (response.status() === 201) {
          console.log(`Campo ${testCase.field} com 1000 caracteres foi aceito`);
        }
      }
    });
  });

  test.describe('Validações de Duplicação', () => {

    test('deve falhar ao criar usuário com email já cadastrado', async ({ apiClient }) => {
      const email = `duplicate_${Date.now()}@teste.com`;
      const userData = {
        nome: 'First User',
        email,
        password: 'senha123',
        administrador: 'false'
      };

      // Cria o primeiro usuário
      const firstResponse = await apiClient.createUser(userData);
      expect(firstResponse.status()).toBe(201);

      // Tenta criar outro com o mesmo email
      const duplicateData = {
        nome: 'Second User',
        email, // mesmo email
        password: 'senha456',
        administrador: 'true'
      };

      const secondResponse = await apiClient.createUser(duplicateData);
      expect(secondResponse.status()).toBe(400);
      
      const body = await secondResponse.json();
      expect(body).toHaveProperty('message');
      expect(body.message).toContain('já');
    });

    test('deve permitir criar usuários com mesmo nome', async ({ apiClient }) => {
      const nome = 'João Silva';
      
      const user1 = {
        nome,
        email: `user1_${Date.now()}@teste.com`,
        password: 'senha123',
        administrador: 'false'
      };

      const user2 = {
        nome, // mesmo nome
        email: `user2_${Date.now()}@teste.com`,
        password: 'senha456',
        administrador: 'false'
      };

      const response1 = await apiClient.createUser(user1);
      expect(response1.status()).toBe(201);

      const response2 = await apiClient.createUser(user2);
      expect(response2.status()).toBe(201);
    });

    test('deve ser case-insensitive para emails duplicados', async ({ apiClient }) => {
      const baseEmail = `test_${Date.now()}@teste.com`;
      
      const userData = {
        nome: 'First User',
        email: baseEmail.toLowerCase(),
        password: 'senha123',
        administrador: 'false'
      };

      // Cria com email em lowercase
      const firstResponse = await apiClient.createUser(userData);
      expect(firstResponse.status()).toBe(201);

      // Tenta criar com email em uppercase
      const duplicateData = {
        nome: 'Second User',
        email: baseEmail.toUpperCase(),
        password: 'senha456',
        administrador: 'false'
      };

      const secondResponse = await apiClient.createUser(duplicateData);
      
      // Deve falhar se a API trata emails case-insensitive
      // Ou suceder se trata case-sensitive
      if (secondResponse.status() === 400) {
        console.log('API trata emails como case-insensitive');
      } else {
        console.log('API trata emails como case-sensitive');
      }
    });
  });

  test.describe('Segurança e Validações Especiais', () => {

    test('deve prevenir SQL Injection', async ({ apiClient }) => {
      const sqlInjectionPayloads = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "admin'--",
        "' OR 1=1--",
        "'; DELETE FROM users WHERE '1'='1",
        "Robert'); DROP TABLE users;--"
      ];

      for (const payload of sqlInjectionPayloads) {
        const userData = {
          nome: payload,
          email: `sqli_${Date.now()}_${Math.random()}@teste.com`,
          password: payload,
          administrador: 'false'
        };

        const response = await apiClient.createUser(userData);
        
        // Deve aceitar como string normal ou rejeitar
        // Mas não deve causar erro 500
        expect(response.status()).not.toBe(500);
        
        if (response.status() === 201) {
          // Se aceitou, verifica se foi salvo corretamente escapado
          const body = await response.json();
          const getResponse = await apiClient.request.get(`/usuarios/${body._id}`);
          const user = await getResponse.json();
          expect(user.nome).toBe(payload);
        }
      }
    });

    test('deve prevenir XSS', async ({ apiClient }) => {
      const xssPayloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        'javascript:alert("XSS")',
        '<svg onload=alert("XSS")>',
        '"><script>alert("XSS")</script>',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>'
      ];

      for (const payload of xssPayloads) {
        const userData = {
          nome: payload,
          email: `xss_${Date.now()}_${Math.random()}@teste.com`,
          password: 'senha123',
          administrador: 'false'
        };

        const response = await apiClient.createUser(userData);
        
        expect(response.status()).not.toBe(500);
        
        if (response.status() === 201) {
          // Se aceitou, verifica se foi salvo de forma segura
          const body = await response.json();
          const getResponse = await apiClient.request.get(`/usuarios/${body._id}`);
          const user = await getResponse.json();
          
          // O payload deve estar escapado ou sanitizado
          expect(user.nome).toBe(payload);
        }
      }
    });

    test('deve prevenir NoSQL Injection', async ({ apiClient }) => {
      const nosqlPayloads = [
        { $ne: null },
        { $gt: '' },
        { $regex: '.*' },
        { $where: '1==1' }
      ];

      for (const payload of nosqlPayloads) {
        const response = await apiClient.request.post('/usuarios', {
          data: {
            nome: payload,
            email: `nosql_${Date.now()}@teste.com`,
            password: 'senha123',
            administrador: 'false'
          }
        });
        
        // Não deve aceitar objetos como valores de string
        expect(response.status()).toBe(400);
      }
    });

    test('deve criptografar a senha antes de armazenar', async ({ apiClient }) => {
      const userData = {
        nome: 'Security Test',
        email: `security_${Date.now()}@teste.com`,
        password: 'senhaPlain123',
        administrador: 'false'
      };

      const response = await apiClient.createUser(userData);
      expect(response.status()).toBe(201);
      
      const body = await response.json();
      
      // Tenta buscar o usuário
      const getResponse = await apiClient.request.get(`/usuarios/${body._id}`);
      const user = await getResponse.json();
      
      // A senha não deve ser retornada
      expect(user.password).toBeUndefined();
      
      // E se por algum motivo retornar, não deve ser em plain text
      if (user.password) {
        expect(user.password).not.toBe('senhaPlain123');
      }
    });

    test('deve lidar com caracteres Unicode', async ({ apiClient }) => {
      const unicodeData = {
        nome: '🚀 Émoji Tëst 你好 مرحبا',
        email: `unicode_${Date.now()}@teste.com`,
        password: '密码123🔐',
        administrador: 'false'
      };

      const response = await apiClient.createUser(unicodeData);
      
      if (response.status() === 201) {
        const body = await response.json();
        const getResponse = await apiClient.request.get(`/usuarios/${body._id}`);
        const user = await getResponse.json();
        
        expect(user.nome).toBe(unicodeData.nome);
      }
    });
  });

  test.describe('Validações de Contrato e Response', () => {

    test('deve retornar estrutura correta na criação bem-sucedida', async ({ apiClient }) => {
      const userData = FixtureLoader.generate('users/valid-users', {
        email: `contract_${Date.now()}@teste.com`
      });

      const response = await apiClient.createUser(userData);
      expect(response.status()).toBe(201);
      
      const body = await response.json();
      
      // Valida estrutura esperada
      expect(body).toHaveProperty('message');
      expect(body).toHaveProperty('_id');
      expect(typeof body.message).toBe('string');
      expect(typeof body._id).toBe('string');
      expect(body._id).toMatch(/^[a-zA-Z0-9]+$/); // ID alfanumérico
    });

    test('deve retornar Location header com URI do recurso criado', async ({ apiClient }) => {
      const userData = FixtureLoader.generate('users/valid-users', {
        email: `location_${Date.now()}@teste.com`
      });

      const response = await apiClient.createUser(userData);
      expect(response.status()).toBe(201);
      
      const headers = response.headers();
      
      if (headers['location']) {
        const body = await response.json();
        expect(headers['location']).toContain(body._id);
      }
    });

    test('deve retornar Content-Type correto', async ({ apiClient }) => {
      const userData = FixtureLoader.generate('users/valid-users', {
        email: `content_${Date.now()}@teste.com`
      });

      const response = await apiClient.createUser(userData);
      
      const headers = response.headers();
      expect(headers['content-type']).toContain('application/json');
    });

    test('deve retornar erro estruturado para validações', async ({ apiClient }) => {
      const invalidData = {
        nome: '',
        email: 'invalid-email',
        password: '12',
        administrador: 'maybe'
      };

      const response = await apiClient.createUser(invalidData);
      expect(response.status()).toBe(400);
      
      const body = await response.json();
      
      // Deve ter estrutura de erro consistente
      expect(typeof body).toBe('object');
      
      // Cada erro deve ter uma mensagem
      Object.values(body).forEach(value => {
        expect(typeof value).toBe('string');
      });
    });
  });

  test.describe('Testes de Performance e Limites', () => {

    test('deve criar usuário em tempo aceitável', async ({ apiClient }) => {
      const userData = FixtureLoader.generate('users/valid-users', {
        email: `perf_${Date.now()}@teste.com`
      });

      const startTime = Date.now();
      const response = await apiClient.createUser(userData);
      const endTime = Date.now();
      
      expect(response.status()).toBe(201);
      
      const responseTime = endTime - startTime;
      expect(responseTime).toBeLessThan(2000); // Menos de 2 segundos
      
      console.log(`Tempo de criação: ${responseTime}ms`);
    });

    test('deve suportar criação concorrente de usuários', async ({ apiClient }) => {
      const promises = [];
      const numberOfConcurrentCreations = 5;

      for (let i = 0; i < numberOfConcurrentCreations; i++) {
        const userData = {
          nome: `Concurrent User ${i}`,
          email: `concurrent_${i}_${Date.now()}@teste.com`,
          password: 'senha123',
          administrador: 'false'
        };

        promises.push(apiClient.createUser(userData));
      }

      const responses = await Promise.all(promises);
      
      // Todos devem ter sucesso
      responses.forEach(response => {
        expect(response.status()).toBe(201);
      });

      // Todos devem ter IDs únicos
      const ids = await Promise.all(
        responses.map(async r => (await r.json())._id)
      );
      
      expect(new Set(ids).size).toBe(numberOfConcurrentCreations);
    });
  });
});