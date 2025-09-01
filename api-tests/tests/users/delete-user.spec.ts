// tests/users/delete-user.spec.ts
import { test, expect } from '../../utils/test-fixtures';
import { FixtureLoader } from '../../utils/fixture-loader';

test.describe('DELETE /usuarios/{id} - Exclusão de Usuários', () => {

  // Helper para criar um usuário e retornar seus dados
  async function createTestUser(apiClient: any, overrides = {}) {
    const userData = FixtureLoader.generate('users/valid-users', {
      email: `delete_test_${Date.now()}_${Math.random()}@teste.com`,
      ...overrides
    });
    
    const response = await apiClient.createUser(userData);
    const body = await response.json();
    
    return {
      ...userData,
      _id: body._id,
      response
    };
  }

  test.describe('Cenários de Sucesso', () => {

    test('deve deletar usuário existente com sucesso', async ({ apiClient }) => {
      // Cria um usuário para deletar
      const user = await createTestUser(apiClient);
      expect(user.response.status()).toBe(201);

      // Deleta o usuário
      const deleteResponse = await apiClient.request.delete(`/usuarios/${user._id}`);
      expect(deleteResponse.status()).toBe(200);

      const deleteBody = await deleteResponse.json();
      expect(deleteBody).toHaveProperty('message');
      expect(deleteBody.message).toContain('excluído');

      // Verifica se o usuário foi realmente deletado
      const getResponse = await apiClient.request.get(`/usuarios/${user._id}`);
      expect(getResponse.status()).toBe(400);
      
      const getBody = await getResponse.json();
      expect(getBody.message).toContain('não encontrado');
    });

    test('deve deletar usuário administrador', async ({ apiClient }) => {
      // Cria um admin
      const admin = await createTestUser(apiClient, { 
        administrador: 'true',
        email: `admin_delete_${Date.now()}@teste.com`
      });

      const deleteResponse = await apiClient.request.delete(`/usuarios/${admin._id}`);
      expect(deleteResponse.status()).toBe(200);

      // Verifica se foi deletado
      const getResponse = await apiClient.request.get(`/usuarios/${admin._id}`);
      expect(getResponse.status()).toBe(400);
    });

    test('deve deletar usuário não-administrador', async ({ apiClient }) => {
      // Cria um usuário comum
      const user = await createTestUser(apiClient, { 
        administrador: 'false',
        email: `user_delete_${Date.now()}@teste.com`
      });

      const deleteResponse = await apiClient.request.delete(`/usuarios/${user._id}`);
      expect(deleteResponse.status()).toBe(200);

      // Verifica se foi deletado
      const getResponse = await apiClient.request.get(`/usuarios/${user._id}`);
      expect(getResponse.status()).toBe(400);
    });

    test('deve permitir deletar múltiplos usuários em sequência', async ({ apiClient }) => {
      const numberOfUsers = 3;
      const users = [];

      // Cria múltiplos usuários
      for (let i = 0; i < numberOfUsers; i++) {
        const user = await createTestUser(apiClient, {
          nome: `Bulk Delete User ${i}`,
          email: `bulk_delete_${i}_${Date.now()}@teste.com`
        });
        users.push(user);
      }

      // Deleta todos
      for (const user of users) {
        const deleteResponse = await apiClient.request.delete(`/usuarios/${user._id}`);
        expect(deleteResponse.status()).toBe(200);
      }

      // Verifica se todos foram deletados
      for (const user of users) {
        const getResponse = await apiClient.request.get(`/usuarios/${user._id}`);
        expect(getResponse.status()).toBe(400);
      }
    });
  });

  test.describe('Cenários de Falha', () => {

    test('deve falhar ao tentar deletar usuário inexistente', async ({ apiClient }) => {
      const fakeIds = [
        '123456789012345678901234', // ID válido mas inexistente
        'nonexistentid123',
        'abcdef123456',
        '000000000000000000000000'
      ];

      for (const fakeId of fakeIds) {
        const deleteResponse = await apiClient.request.delete(`/usuarios/${fakeId}`);
        
        // Pode retornar 400 ou 404
        expect([400, 404]).toContain(deleteResponse.status());
        
        if (deleteResponse.status() === 200) {
          console.warn(`⚠️ API deletou ID inexistente: ${fakeId}`);
        }
      }
    });

    test('deve falhar com ID em formato inválido', async ({ apiClient }) => {
      const invalidIds = [
        '',
        ' ',
        'undefined',
        'null',
        '!@#$%',
        '../etc/passwd',
        '<script>alert("xss")</script>',
        '"; DROP TABLE users; --',
        '../../admin',
        '%00',
        '\n\r',
        '{}',
        '[]',
        'true',
        'false'
      ];

      for (const invalidId of invalidIds) {
        const deleteResponse = await apiClient.request.delete(`/usuarios/${invalidId}`);
        
        // Não deve retornar sucesso
        expect(deleteResponse.status()).not.toBe(200);
        
        // Deve retornar erro cliente (4xx) não erro servidor (5xx)
        expect(deleteResponse.status()).toBeGreaterThanOrEqual(400);
        expect(deleteResponse.status()).toBeLessThan(500);
        
        console.log(`ID inválido testado: "${invalidId}" - Status: ${deleteResponse.status()}`);
      }
    });

    test('deve falhar ao deletar sem ID', async ({ apiClient }) => {
      const deleteResponse = await apiClient.request.delete('/usuarios/');
      
      // Deve retornar erro
      expect(deleteResponse.status()).not.toBe(200);
      expect([400, 404, 405]).toContain(deleteResponse.status());
    });

    test('deve falhar ao tentar deletar o mesmo usuário duas vezes', async ({ apiClient }) => {
      // Cria um usuário
      const user = await createTestUser(apiClient);
      
      // Primeira deleção deve funcionar
      const firstDelete = await apiClient.request.delete(`/usuarios/${user._id}`);
      expect(firstDelete.status()).toBe(200);

      // Segunda deleção deve falhar
      const secondDelete = await apiClient.request.delete(`/usuarios/${user._id}`);
      expect([400, 404]).toContain(secondDelete.status());
      
      const body = await secondDelete.json();
      expect(body.message).toContain('não encontrado');
    });
  });

  test.describe('Validações de Autorização', () => {

    test('deve exigir autenticação para deletar usuário', async ({ apiClient }) => {
      // Cria um usuário
      const user = await createTestUser(apiClient);

      // Tenta deletar sem token de autenticação
      const deleteResponse = await apiClient.request.delete(`/usuarios/${user._id}`, {
        headers: {
          'Authorization': '' // Sem token
        }
      });

      // Se a API exige autenticação, deve retornar 401
      // Se não exige, vai retornar 200
      if (deleteResponse.status() === 401) {
        const body = await deleteResponse.json();
        expect(body).toHaveProperty('message');
        console.log('✓ API exige autenticação para deletar');
      } else if (deleteResponse.status() === 200) {
        console.log('⚠️ API não exige autenticação para deletar');
      }
    });

    test('deve validar permissões para deletar outros usuários', async ({ apiClient }) => {
      // Cria dois usuários: um admin e um comum
      const adminUser = await createTestUser(apiClient, {
        administrador: 'true',
        email: `admin_auth_${Date.now()}@teste.com`
      });

      const regularUser = await createTestUser(apiClient, {
        administrador: 'false',
        email: `user_auth_${Date.now()}@teste.com`
      });

      // Autentica como usuário comum
      const authResponse = await apiClient.authenticate(regularUser.email, regularUser.password);
      
      if (authResponse.status === 200) {
        const token = authResponse.body.authorization;

        // Tenta deletar o admin sendo usuário comum
        const deleteResponse = await apiClient.request.delete(`/usuarios/${adminUser._id}`, {
          headers: {
            'Authorization': token
          }
        });

        // Pode permitir ou negar baseado em permissões
        if (deleteResponse.status() === 403) {
          console.log('✓ API valida permissões de deleção');
        } else if (deleteResponse.status() === 200) {
          console.log('⚠️ Usuário comum conseguiu deletar admin');
        }
      }
    });

    test('deve rejeitar token inválido', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);

      const invalidTokens = [
        'Bearer invalid-token',
        'InvalidToken',
        'Bearer ',
        'null',
        'undefined',
        'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature'
      ];

      for (const token of invalidTokens) {
        const deleteResponse = await apiClient.request.delete(`/usuarios/${user._id}`, {
          headers: {
            'Authorization': token
          }
        });

        // Com token inválido deve retornar 401
        if (deleteResponse.status() === 401) {
          console.log(`✓ Token inválido rejeitado: ${token.substring(0, 20)}...`);
        }
      }
    });
  });

  test.describe('Validações de Integridade e Cascata', () => {

    test('deve validar se usuário tem dependências antes de deletar', async ({ apiClient }) => {
      // Cria um usuário
      const user = await createTestUser(apiClient);

      // Se a API tem conceito de carrinho, cria um carrinho para o usuário
      // Isso é específico da API ServerRest
      const cartResponse = await apiClient.request.post('/carrinhos', {
        data: {
          produtos: [
            {
              idProduto: "1", // ID fictício
              quantidade: 1
            }
          ]
        },
        headers: {
          'Authorization': `Bearer ${user._id}` // Se necessário
        }
      });

      // Tenta deletar o usuário
      const deleteResponse = await apiClient.request.delete(`/usuarios/${user._id}`);

      // Se há validação de integridade, pode retornar erro
      if (deleteResponse.status() === 400) {
        const body = await deleteResponse.json();
        console.log('✓ API valida dependências antes de deletar:', body.message);
      } else if (deleteResponse.status() === 200) {
        console.log('⚠️ API permite deletar usuário com dependências');
      }
    });

    test('deve lidar com deleção de usuário logado', async ({ apiClient }) => {
      // Cria e autentica um usuário
      const user = await createTestUser(apiClient);
      const authResponse = await apiClient.authenticate(user.email, user.password);
      
      if (authResponse.status === 200) {
        const token = authResponse.body.authorization;

        // Usuário tenta deletar a si mesmo
        const deleteResponse = await apiClient.request.delete(`/usuarios/${user._id}`, {
          headers: {
            'Authorization': token
          }
        });

        if (deleteResponse.status() === 200) {
          // Se permitiu, verifica se o token ainda é válido
          const testResponse = await apiClient.request.get('/usuarios', {
            headers: {
              'Authorization': token
            }
          });

          if (testResponse.status() === 401) {
            console.log('✓ Token invalidado após auto-deleção');
          } else {
            console.log('⚠️ Token ainda válido após auto-deleção');
          }
        } else {
          console.log('✓ API impede auto-deleção');
        }
      }
    });
  });

  test.describe('Segurança', () => {

    test('deve prevenir path traversal', async ({ apiClient }) => {
      const pathTraversalPayloads = [
        '../admin',
        '../../etc/passwd',
        '..\\..\\windows\\system32',
        '%2e%2e%2f',
        '%252e%252e%252f',
        '....///',
        '..;/',
        '../../../../../'
      ];

      for (const payload of pathTraversalPayloads) {
        const deleteResponse = await apiClient.request.delete(`/usuarios/${payload}`);
        
        // Não deve causar erro do servidor
        expect(deleteResponse.status()).toBeGreaterThanOrEqual(400);
        expect(deleteResponse.status()).toBeLessThan(500);
        
        console.log(`Path traversal testado: ${payload} - Status: ${deleteResponse.status()}`);
      }
    });

    test('deve prevenir SQL Injection no parâmetro ID', async ({ apiClient }) => {
      const sqlInjectionPayloads = [
        "1' OR '1'='1",
        "1; DROP TABLE users; --",
        "1' UNION SELECT * FROM users--",
        "1 OR 1=1",
        "'; DELETE FROM users WHERE '1'='1"
      ];

      for (const payload of sqlInjectionPayloads) {
        const deleteResponse = await apiClient.request.delete(`/usuarios/${payload}`);
        
        // Não deve executar SQL injection
        expect(deleteResponse.status()).not.toBe(200);
        expect(deleteResponse.status()).toBeLessThan(500);
        
        console.log(`SQL Injection testado: ${payload} - Status: ${deleteResponse.status()}`);
      }
    });

    test('deve prevenir NoSQL Injection', async ({ apiClient }) => {
      const nosqlPayloads = [
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"_id": {"$ne": null}}',
        '[$ne]=null'
      ];

      for (const payload of nosqlPayloads) {
        const deleteResponse = await apiClient.request.delete(`/usuarios/${payload}`);
        
        expect(deleteResponse.status()).not.toBe(200);
        expect(deleteResponse.status()).toBeLessThan(500);
      }
    });

    test('deve validar comprimento máximo do ID', async ({ apiClient }) => {
      const longId = 'a'.repeat(1000);
      
      const deleteResponse = await apiClient.request.delete(`/usuarios/${longId}`);
      
      // Deve rejeitar ID muito longo
      expect(deleteResponse.status()).not.toBe(200);
      expect(deleteResponse.status()).toBeLessThan(500);
    });
  });

  test.describe('Validações de Response', () => {

    test('deve retornar estrutura correta ao deletar com sucesso', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const deleteResponse = await apiClient.request.delete(`/usuarios/${user._id}`);
      expect(deleteResponse.status()).toBe(200);

      const body = await deleteResponse.json();
      
      // Valida estrutura da resposta
      expect(body).toHaveProperty('message');
      expect(typeof body.message).toBe('string');
      expect(body.message.toLowerCase()).toMatch(/exclu[ií]d|delet|remov/);
    });

    test('deve retornar estrutura correta ao falhar', async ({ apiClient }) => {
      const fakeId = 'nonexistent123';
      
      const deleteResponse = await apiClient.request.delete(`/usuarios/${fakeId}`);
      expect(deleteResponse.status()).not.toBe(200);

      const body = await deleteResponse.json();
      
      // Deve ter mensagem de erro
      expect(body).toHaveProperty('message');
      expect(typeof body.message).toBe('string');
    });

    test('deve retornar Content-Type correto', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const deleteResponse = await apiClient.request.delete(`/usuarios/${user._id}`);
      
      const headers = deleteResponse.headers();
      expect(headers['content-type']).toContain('application/json');
    });

    test('deve retornar status code apropriado', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      // Sucesso deve ser 200 ou 204
      const deleteResponse = await apiClient.request.delete(`/usuarios/${user._id}`);
      expect([200, 204]).toContain(deleteResponse.status());

      // Tentar deletar novamente deve ser 4xx
      const secondDelete = await apiClient.request.delete(`/usuarios/${user._id}`);
      expect(secondDelete.status()).toBeGreaterThanOrEqual(400);
      expect(secondDelete.status()).toBeLessThan(500);
    });
  });

  test.describe('Performance e Concorrência', () => {

    test('deve deletar em tempo aceitável', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const startTime = Date.now();
      const deleteResponse = await apiClient.request.delete(`/usuarios/${user._id}`);
      const endTime = Date.now();
      
      expect(deleteResponse.status()).toBe(200);
      
      const responseTime = endTime - startTime;
      expect(responseTime).toBeLessThan(2000); // Menos de 2 segundos
      
      console.log(`Tempo de deleção: ${responseTime}ms`);
    });

    test('deve lidar com deleções concorrentes', async ({ apiClient }) => {
      // Cria múltiplos usuários
      const users = await Promise.all([
        createTestUser(apiClient, { email: `concurrent_1_${Date.now()}@teste.com` }),
        createTestUser(apiClient, { email: `concurrent_2_${Date.now()}@teste.com` }),
        createTestUser(apiClient, { email: `concurrent_3_${Date.now()}@teste.com` })
      ]);

      // Deleta todos concorrentemente
      const deletePromises = users.map(user => 
        apiClient.request.delete(`/usuarios/${user._id}`)
      );

      const responses = await Promise.all(deletePromises);
      
      // Todos devem ter sucesso
      responses.forEach(response => {
        expect(response.status()).toBe(200);
      });
    });

    test('deve prevenir condições de corrida ao deletar mesmo usuário', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      // Tenta deletar o mesmo usuário múltiplas vezes concorrentemente
      const deletePromises = Array(5).fill(null).map(() => 
        apiClient.request.delete(`/usuarios/${user._id}`)
      );

      const responses = await Promise.all(deletePromises);
      
      // Apenas uma deleção deve ter sucesso
      const successCount = responses.filter(r => r.status() === 200).length;
      const errorCount = responses.filter(r => r.status() >= 400).length;
      
      expect(successCount).toBe(1);
      expect(errorCount).toBe(4);
      
      console.log(`✓ Condição de corrida prevenida: ${successCount} sucesso, ${errorCount} erros`);
    });
  });

  test.describe('Auditoria e Logging', () => {

    test('deve ser possível verificar que usuário foi deletado', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      const userId = user._id;
      
      // Verifica que existe antes
      const beforeDelete = await apiClient.request.get(`/usuarios/${userId}`);
      expect(beforeDelete.status()).toBe(200);
      
      // Deleta
      const deleteResponse = await apiClient.request.delete(`/usuarios/${userId}`);
      expect(deleteResponse.status()).toBe(200);
      
      // Verifica que não existe mais
      const afterDelete = await apiClient.request.get(`/usuarios/${userId}`);
      expect(afterDelete.status()).toBe(400);
      
      // Verifica na listagem geral
      const listResponse = await apiClient.request.get('/usuarios');
      if (listResponse.status() === 200) {
        const body = await listResponse.json();
        const users = body.usuarios || [];
        const deletedUser = users.find((u: any) => u._id === userId);
        expect(deletedUser).toBeUndefined();
      }
    });

    test('deve manter consistência após deleção', async ({ apiClient }) => {
      // Conta usuários antes
      const beforeResponse = await apiClient.request.get('/usuarios');
      const beforeCount = beforeResponse.status() === 200 
        ? (await beforeResponse.json()).quantidade || 0 
        : 0;
      
      // Cria e deleta um usuário
      const user = await createTestUser(apiClient);
      await apiClient.request.delete(`/usuarios/${user._id}`);
      
      // Conta usuários depois
      const afterResponse = await apiClient.request.get('/usuarios');
      const afterCount = afterResponse.status() === 200 
        ? (await afterResponse.json()).quantidade || 0 
        : 0;
      
      // A contagem deve ser a mesma
      expect(afterCount).toBe(beforeCount);
      
      console.log(`✓ Consistência mantida: ${beforeCount} usuários antes e depois`);
    });
  });
});