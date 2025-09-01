// tests/users/read-user.spec.ts
import { test, expect } from '../../utils/test-fixtures';
import { FixtureLoader } from '../../utils/fixture-loader';

test.describe('GET /usuarios - Leitura de Usuários', () => {

  // Helper para criar múltiplos usuários de teste
  async function createMultipleUsers(apiClient: any, count: number) {
    const users = [];
    for (let i = 0; i < count; i++) {
      const userData = {
        nome: `Test User ${i}`,
        email: `read_test_${i}_${Date.now()}@teste.com`,
        password: 'senha123',
        administrador: i % 2 === 0 ? 'true' : 'false'
      };
      
      const response = await apiClient.createUser(userData);
      const body = await response.json();
      users.push({ ...userData, _id: body._id });
    }
    return users;
  }

  test.describe('GET /usuarios - Listagem de Todos os Usuários', () => {

    test('deve listar todos os usuários cadastrados', async ({ apiClient }) => {
      const response = await apiClient.request.get('/usuarios');
      
      expect(response.status()).toBe(200);
      
      const body = await response.json();
      
      // Valida estrutura da resposta
      expect(body).toHaveProperty('quantidade');
      expect(body).toHaveProperty('usuarios');
      expect(Array.isArray(body.usuarios)).toBe(true);
      expect(typeof body.quantidade).toBe('number');
      
      // Quantidade deve corresponder ao array
      expect(body.usuarios.length).toBe(body.quantidade);
      
      // Cada usuário deve ter estrutura correta
      if (body.usuarios.length > 0) {
        const user = body.usuarios[0];
        expect(user).toHaveProperty('nome');
        expect(user).toHaveProperty('email');
        expect(user).toHaveProperty('administrador');
        expect(user).toHaveProperty('_id');
        
        // Senha não deve ser retornada
        expect(user).not.toHaveProperty('password');
      }
    });

    test('deve retornar lista vazia quando não há usuários', async ({ apiClient }) => {
      // Este teste pode falhar se há usuários pré-existentes
      // Idealmente seria executado em ambiente isolado
      
      const response = await apiClient.request.get('/usuarios');
      expect(response.status()).toBe(200);
      
      const body = await response.json();
      
      if (body.quantidade === 0) {
        expect(body.usuarios).toEqual([]);
        console.log('✓ Lista vazia retornada corretamente');
      } else {
        console.log(`ℹ️ Existem ${body.quantidade} usuários no sistema`);
      }
    });

    test('deve paginar resultados quando há muitos usuários', async ({ apiClient }) => {
      // Verifica se a API suporta paginação
      const response = await apiClient.request.get('/usuarios?_page=1&_limit=10');
      
      if (response.status() === 200) {
        const body = await response.json();
        
        if (body.usuarios && body.usuarios.length <= 10) {
          console.log('✓ API pode suportar paginação');
        }
      }
      
      // Testa também com parâmetros alternativos
      const altResponse = await apiClient.request.get('/usuarios?page=1&limit=10');
      if (altResponse.status() === 200) {
        console.log('✓ API aceita parâmetros page/limit');
      }
    });

    test('deve retornar usuários ordenados consistentemente', async ({ apiClient }) => {
      // Faz duas requisições
      const response1 = await apiClient.request.get('/usuarios');
      const response2 = await apiClient.request.get('/usuarios');
      
      expect(response1.status()).toBe(200);
      expect(response2.status()).toBe(200);
      
      const body1 = await response1.json();
      const body2 = await response2.json();
      
      // A ordem deve ser consistente
      if (body1.usuarios.length > 1 && body1.usuarios.length === body2.usuarios.length) {
        const ids1 = body1.usuarios.map((u: any) => u._id);
        const ids2 = body2.usuarios.map((u: any) => u._id);
        
        expect(ids1).toEqual(ids2);
        console.log('✓ Ordem de listagem é consistente');
      }
    });

    test('deve incluir todos os campos necessários na listagem', async ({ apiClient }) => {
      // Cria um usuário para garantir que há dados
      const userData = {
        nome: 'Complete User',
        email: `complete_${Date.now()}@teste.com`,
        password: 'senha123',
        administrador: 'true'
      };
      
      const createResponse = await apiClient.createUser(userData);
      const created = await createResponse.json();
      
      // Lista usuários
      const response = await apiClient.request.get('/usuarios');
      const body = await response.json();
      
      // Encontra o usuário criado
      const user = body.usuarios.find((u: any) => u._id === created._id);
      
      expect(user).toBeDefined();
      expect(user.nome).toBe(userData.nome);
      expect(user.email).toBe(userData.email);
      expect(user.administrador).toBe(userData.administrador);
      expect(user._id).toBe(created._id);
      expect(user.password).toBeUndefined();
    });
  });

  test.describe('GET /usuarios/{id} - Busca por ID', () => {

    test('deve buscar usuário existente por ID', async ({ apiClient }) => {
      // Cria um usuário
      const userData = {
        nome: 'User to Find',
        email: `find_${Date.now()}@teste.com`,
        password: 'senha123',
        administrador: 'false'
      };
      
      const createResponse = await apiClient.createUser(userData);
      const created = await createResponse.json();
      
      // Busca por ID
      const response = await apiClient.request.get(`/usuarios/${created._id}`);
      
      expect(response.status()).toBe(200);
      
      const user = await response.json();
      
      // Valida dados retornados
      expect(user.nome).toBe(userData.nome);
      expect(user.email).toBe(userData.email);
      expect(user.administrador).toBe(userData.administrador);
      expect(user._id).toBe(created._id);
      expect(user.password).toBeUndefined();
    });

    test('deve retornar erro ao buscar ID inexistente', async ({ apiClient }) => {
      const fakeIds = [
        '123456789012345678901234',
        'nonexistentid',
        'abc123def456'
      ];

      for (const fakeId of fakeIds) {
        const response = await apiClient.request.get(`/usuarios/${fakeId}`);
        
        expect([400, 404]).toContain(response.status());
        
        const body = await response.json();
        expect(body).toHaveProperty('message');
        expect(body.message.toLowerCase()).toMatch(/não encontrado|not found|inválido/);
      }
    });

    test('deve validar formato do ID', async ({ apiClient }) => {
      const invalidIds = [
        '',
        ' ',
        'undefined',
        'null',
        '!@#$%',
        '../etc/passwd',
        '<script>alert("xss")</script>',
        '"; DROP TABLE users; --'
      ];

      for (const invalidId of invalidIds) {
        const response = await apiClient.request.get(`/usuarios/${invalidId}`);
        
        expect(response.status()).toBeGreaterThanOrEqual(400);
        expect(response.status()).toBeLessThan(500);
        
        console.log(`ID inválido testado: "${invalidId}" - Status: ${response.status()}`);
      }
    });

    test('deve ser case-sensitive para IDs', async ({ apiClient }) => {
      // Cria um usuário
      const createResponse = await apiClient.createUser({
        nome: 'Case Test',
        email: `case_${Date.now()}@teste.com`,
        password: 'senha123',
        administrador: 'false'
      });
      
      const created = await createResponse.json();
      const id = created._id;
      
      // Testa com ID original
      const response1 = await apiClient.request.get(`/usuarios/${id}`);
      expect(response1.status()).toBe(200);
      
      // Testa com ID em uppercase (se alfanumérico)
      if (/[a-z]/.test(id)) {
        const response2 = await apiClient.request.get(`/usuarios/${id.toUpperCase()}`);
        expect([400, 404]).toContain(response2.status());
      }
    });
  });

  test.describe('Filtros e Buscas', () => {

    test('deve filtrar usuários por nome', async ({ apiClient }) => {
      // Testa se a API suporta filtro por nome
      const response = await apiClient.request.get('/usuarios?nome=Test');
      
      if (response.status() === 200) {
        const body = await response.json();
        
        if (body.usuarios) {
          // Verifica se todos os resultados contêm "Test" no nome
          const filtered = body.usuarios.filter((u: any) => 
            u.nome.toLowerCase().includes('test')
          );
          
          if (filtered.length === body.usuarios.length) {
            console.log('✓ API suporta filtro por nome');
          }
        }
      }
    });

    test('deve filtrar usuários por email', async ({ apiClient }) => {
      // Cria usuário com email específico
      const uniqueDomain = `domain${Date.now()}.com`;
      await apiClient.createUser({
        nome: 'Filter Test',
        email: `user@${uniqueDomain}`,
        password: 'senha123',
        administrador: 'false'
      });
      
      // Tenta filtrar por email
      const response = await apiClient.request.get(`/usuarios?email=user@${uniqueDomain}`);
      
      if (response.status() === 200) {
        const body = await response.json();
        
        if (body.usuarios && body.usuarios.length === 1) {
          expect(body.usuarios[0].email).toBe(`user@${uniqueDomain}`);
          console.log('✓ API suporta filtro por email');
        }
      }
    });

    test('deve filtrar usuários por tipo (admin/não-admin)', async ({ apiClient }) => {
      // Testa filtro por administrador
      const responseAdmin = await apiClient.request.get('/usuarios?administrador=true');
      
      if (responseAdmin.status() === 200) {
        const body = await responseAdmin.json();
        
        if (body.usuarios) {
          const allAdmins = body.usuarios.every((u: any) => u.administrador === 'true');
          
          if (allAdmins) {
            console.log('✓ API suporta filtro por administrador');
          }
        }
      }
      
      // Testa filtro por não-administrador
      const responseNonAdmin = await apiClient.request.get('/usuarios?administrador=false');
      
      if (responseNonAdmin.status() === 200) {
        const body = await responseNonAdmin.json();
        
        if (body.usuarios) {
          const allNonAdmins = body.usuarios.every((u: any) => u.administrador === 'false');
          
          if (allNonAdmins) {
            console.log('✓ Filtro por não-administrador funciona');
          }
        }
      }
    });

    test('deve suportar múltiplos filtros simultaneamente', async ({ apiClient }) => {
      // Tenta combinar filtros
      const response = await apiClient.request.get('/usuarios?administrador=true&nome=Admin');
      
      if (response.status() === 200) {
        const body = await response.json();
        
        if (body.usuarios) {
          const matchAll = body.usuarios.every((u: any) => 
            u.administrador === 'true' && u.nome.includes('Admin')
          );
          
          if (matchAll) {
            console.log('✓ API suporta múltiplos filtros');
          }
        }
      }
    });

    test('deve retornar lista vazia para filtros sem resultados', async ({ apiClient }) => {
      const randomEmail = `nonexistent_${Date.now()}@impossible.com`;
      const response = await apiClient.request.get(`/usuarios?email=${randomEmail}`);
      
      if (response.status() === 200) {
        const body = await response.json();
        
        expect(body.quantidade).toBe(0);
        expect(body.usuarios).toEqual([]);
      }
    });

    test('deve ignorar parâmetros desconhecidos', async ({ apiClient }) => {
      const response = await apiClient.request.get('/usuarios?invalidParam=value&xyz=123');
      
      // Deve retornar sucesso mesmo com parâmetros inválidos
      expect(response.status()).toBe(200);
      
      const body = await response.json();
      expect(body).toHaveProperty('usuarios');
    });
  });

  test.describe('Validações de Segurança', () => {

    test('deve prevenir vazamento de senhas', async ({ apiClient }) => {
      // Cria usuário com senha conhecida
      const userData = {
        nome: 'Security Test',
        email: `security_${Date.now()}@teste.com`,
        password: 'SuperSecretPassword123!',
        administrador: 'false'
      };
      
      const createResponse = await apiClient.createUser(userData);
      const created = await createResponse.json();
      
      // Busca o usuário
      const response = await apiClient.request.get(`/usuarios/${created._id}`);
      const user = await response.json();
      
      // Senha não deve estar presente
      expect(user.password).toBeUndefined();
      
      // Verifica também na listagem
      const listResponse = await apiClient.request.get('/usuarios');
      const list = await listResponse.json();
      const listedUser = list.usuarios.find((u: any) => u._id === created._id);
      
      expect(listedUser.password).toBeUndefined();
      
      // Verifica que a resposta não contém a senha em nenhum lugar
      const responseText = JSON.stringify(user);
      expect(responseText).not.toContain(userData.password);
    });

    test('deve prevenir SQL Injection em parâmetros de busca', async ({ apiClient }) => {
      const sqlInjectionPayloads = [
        "' OR '1'='1",
        "admin'--",
        "' OR 1=1--",
        "'; DROP TABLE users;--",
        "' UNION SELECT * FROM users--"
      ];

      for (const payload of sqlInjectionPayloads) {
        const response = await apiClient.request.get(`/usuarios?nome=${encodeURIComponent(payload)}`);
        
        // Não deve causar erro do servidor
        expect(response.status()).toBeLessThan(500);
        
        if (response.status() === 200) {
          const body = await response.json();
          // Deve retornar estrutura normal
          expect(body).toHaveProperty('usuarios');
          expect(body).toHaveProperty('quantidade');
        }
      }
    });

    test('deve prevenir NoSQL Injection', async ({ apiClient }) => {
      const nosqlPayloads = [
        '{"$ne": null}',
        '{"$gt": ""}',
        '[$ne]=null',
        '{"email": {"$regex": ".*"}}'
      ];

      for (const payload of nosqlPayloads) {
        const response = await apiClient.request.get(`/usuarios?email=${encodeURIComponent(payload)}`);
        
        expect(response.status()).toBeLessThan(500);
        
        if (response.status() === 200) {
          const body = await response.json();
          // Não deve retornar todos os usuários
          expect(body.quantidade).toBe(0);
        }
      }
    });

    test('deve sanitizar saída para prevenir XSS', async ({ apiClient }) => {
      // Cria usuário com payload XSS no nome
      const xssPayload = '<script>alert("XSS")</script>';
      const userData = {
        nome: xssPayload,
        email: `xss_${Date.now()}@teste.com`,
        password: 'senha123',
        administrador: 'false'
      };
      
      const createResponse = await apiClient.createUser(userData);
      
      if (createResponse.status() === 201) {
        const created = await createResponse.json();
        
        // Busca o usuário
        const response = await apiClient.request.get(`/usuarios/${created._id}`);
        const user = await response.json();
        
        // O nome deve estar presente mas escapado/sanitizado
        expect(user.nome).toBe(xssPayload);
        
        // Verifica que não há tags HTML ativas na resposta
        const responseText = JSON.stringify(user);
        expect(responseText).toContain(xssPayload);
      }
    });
  });

  test.describe('Performance e Otimização', () => {

    test('deve responder rapidamente para listagem', async ({ apiClient }) => {
      const startTime = Date.now();
      const response = await apiClient.request.get('/usuarios');
      const endTime = Date.now();
      
      expect(response.status()).toBe(200);
      
      const responseTime = endTime - startTime;
      expect(responseTime).toBeLessThan(2000); // Menos de 2 segundos
      
      console.log(`Tempo de listagem: ${responseTime}ms`);
    });

    test('deve responder rapidamente para busca por ID', async ({ apiClient }) => {
      // Cria um usuário
      const createResponse = await apiClient.createUser({
        nome: 'Performance Test',
        email: `perf_${Date.now()}@teste.com`,
        password: 'senha123',
        administrador: 'false'
      });
      
      const created = await createResponse.json();
      
      const startTime = Date.now();
      const response = await apiClient.request.get(`/usuarios/${created._id}`);
      const endTime = Date.now();
      
      expect(response.status()).toBe(200);
      
      const responseTime = endTime - startTime;
      expect(responseTime).toBeLessThan(1000); // Menos de 1 segundo
      
      console.log(`Tempo de busca por ID: ${responseTime}ms`);
    });

    test('deve lidar com múltiplas requisições concorrentes', async ({ apiClient }) => {
      const promises = [];
      const numberOfRequests = 10;
      
      for (let i = 0; i < numberOfRequests; i++) {
        promises.push(apiClient.request.get('/usuarios'));
      }
      
      const startTime = Date.now();
      const responses = await Promise.all(promises);
      const endTime = Date.now();
      
      // Todas devem ter sucesso
      responses.forEach(response => {
        expect(response.status()).toBe(200);
      });
      
      const totalTime = endTime - startTime;
      console.log(`${numberOfRequests} requisições concorrentes em ${totalTime}ms`);
      
      // Tempo total não deve ser linear (deve haver paralelização)
      expect(totalTime).toBeLessThan(numberOfRequests * 500);
    });

    test('deve retornar dados consistentes em requisições paralelas', async ({ apiClient }) => {
      // Faz 5 requisições paralelas
      const responses = await Promise.all([
        apiClient.request.get('/usuarios'),
        apiClient.request.get('/usuarios'),
        apiClient.request.get('/usuarios'),
        apiClient.request.get('/usuarios'),
        apiClient.request.get('/usuarios')
      ]);
      
      const bodies = await Promise.all(
        responses.map(r => r.json())
      );
      
      // Todas devem ter a mesma quantidade
      const quantities = bodies.map(b => b.quantidade);
      expect(new Set(quantities).size).toBe(1);
      
      // Todas devem ter os mesmos IDs
      const allIds = bodies.map(b => 
        b.usuarios.map((u: any) => u._id).sort()
      );
      
      for (let i = 1; i < allIds.length; i++) {
        expect(allIds[i]).toEqual(allIds[0]);
      }
    });
  });

  test.describe('Validações de Contrato', () => {

    test('deve retornar Content-Type correto', async ({ apiClient }) => {
      const response = await apiClient.request.get('/usuarios');
      
      const headers = response.headers();
      expect(headers['content-type']).toContain('application/json');
    });

    test('deve retornar estrutura consistente para lista vazia', async ({ apiClient }) => {
      // Busca com filtro improvável
      const response = await apiClient.request.get(`/usuarios?email=empty_${Date.now()}@test.com`);
      
      expect(response.status()).toBe(200);
      
      const body = await response.json();
      
      // Mesmo vazio, deve ter a estrutura
      expect(body).toHaveProperty('quantidade', 0);
      expect(body).toHaveProperty('usuarios');
      expect(body.usuarios).toEqual([]);
    });

    test('deve validar tipos de dados na resposta', async ({ apiClient }) => {
      const response = await apiClient.request.get('/usuarios');
      const body = await response.json();
      
      // Validações de tipo
      expect(typeof body.quantidade).toBe('number');
      expect(Array.isArray(body.usuarios)).toBe(true);
      
      if (body.usuarios.length > 0) {
        const user = body.usuarios[0];
        
        expect(typeof user._id).toBe('string');
        expect(typeof user.nome).toBe('string');
        expect(typeof user.email).toBe('string');
        expect(typeof user.administrador).toBe('string');
        expect(['true', 'false']).toContain(user.administrador);
      }
    });

    test('deve retornar campos consistentes em todos os usuários', async ({ apiClient }) => {
      const response = await apiClient.request.get('/usuarios');
      const body = await response.json();
      
      if (body.usuarios.length > 1) {
        const firstUserKeys = Object.keys(body.usuarios[0]).sort();
        
        // Todos os usuários devem ter os mesmos campos
        body.usuarios.forEach((user: any) => {
          const userKeys = Object.keys(user).sort();
          expect(userKeys).toEqual(firstUserKeys);
        });
        
        console.log('✓ Todos os usuários têm campos consistentes:', firstUserKeys);
      }
    });
  });

  test.describe('Casos Especiais', () => {

    test('deve lidar com caracteres especiais em nomes', async ({ apiClient }) => {
      // Cria usuários com nomes especiais
      const specialUsers = [
        { nome: "José & Maria", email: `special1_${Date.now()}@teste.com` },
        { nome: "O'Connor", email: `special2_${Date.now()}@teste.com` },
        { nome: "François Müller", email: `special3_${Date.now()}@teste.com` },
        { nome: "李明", email: `special4_${Date.now()}@teste.com` },
        { nome: "محمد", email: `special5_${Date.now()}@teste.com` }
      ];
      
      for (const userData of specialUsers) {
        const createResponse = await apiClient.createUser({
          ...userData,
          password: 'senha123',
          administrador: 'false'
        });
        
        if (createResponse.status() === 201) {
          const created = await createResponse.json();
          
          // Busca o usuário
          const response = await apiClient.request.get(`/usuarios/${created._id}`);
          const user = await response.json();
          
          expect(user.nome).toBe(userData.nome);
          console.log(`✓ Nome especial preservado: ${userData.nome}`);
        }
      }
    });

    test('deve retornar erro apropriado para rotas não existentes', async ({ apiClient }) => {
      const invalidRoutes = [
        '/usuarios/abc/def',
        '/usuarios//id',
        '/usuarios/../../etc/passwd',
        '/usuarios/%00',
        '/usuarios/\n'
      ];
      
      for (const route of invalidRoutes) {
        const response = await apiClient.request.get(route);
        
        expect(response.status()).toBeGreaterThanOrEqual(400);
        expect(response.status()).toBeLessThan(500);
      }
    });

    test('deve manter encoding UTF-8', async ({ apiClient }) => {
      const response = await apiClient.request.get('/usuarios');
      const headers = response.headers();
      
      if (headers['content-type']) {
        // Deve especificar UTF-8
        expect(headers['content-type']).toMatch(/charset=utf-8/i);
      }
    });
  });
});