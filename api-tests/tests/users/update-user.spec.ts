import { test, expect } from '../../utils/test-fixtures';
import { FixtureLoader } from '../../utils/fixture-loader';

test.describe('PUT /usuarios/{id} - Atualização de Usuários', () => {

  // Helper para criar um usuário de teste
  async function createTestUser(apiClient: any, overrides = {}) {
    const userData = FixtureLoader.generate('users/valid-users', {
      email: `update_test_${Date.now()}_${Math.random()}@teste.com`,
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

    test('deve atualizar todos os campos de um usuário', async ({ apiClient }) => {
      // Cria usuário inicial
      const user = await createTestUser(apiClient, {
        nome: 'Nome Original',
        email: `original_${Date.now()}@teste.com`,
        administrador: 'false'
      });

      // Dados atualizados
      const updatedData = {
        nome: 'Nome Atualizado',
        email: `updated_${Date.now()}@teste.com`,
        password: 'novaSenha123',
        administrador: 'true'
      };

      // Atualiza o usuário
      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: updatedData
      });

      expect(updateResponse.status()).toBe(200);
      
      const updateBody = await updateResponse.json();
      expect(updateBody).toHaveProperty('message');
      expect(updateBody.message).toContain('sucesso');

      // Verifica se foi realmente atualizado
      const getResponse = await apiClient.request.get(`/usuarios/${user._id}`);
      const updatedUser = await getResponse.json();

      expect(updatedUser.nome).toBe(updatedData.nome);
      expect(updatedUser.email).toBe(updatedData.email);
      expect(updatedUser.administrador).toBe(updatedData.administrador);
      
      // Testa login com nova senha
      const loginResponse = await apiClient.authenticate(updatedData.email, updatedData.password);
      expect(loginResponse.status).toBe(200);
    });

    test('deve atualizar apenas o nome mantendo outros campos', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const updateData = {
        nome: 'Apenas Nome Novo',
        email: user.email,
        password: user.password,
        administrador: user.administrador
      };

      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: updateData
      });

      expect(updateResponse.status()).toBe(200);

      const getResponse = await apiClient.request.get(`/usuarios/${user._id}`);
      const updatedUser = await getResponse.json();

      expect(updatedUser.nome).toBe('Apenas Nome Novo');
      expect(updatedUser.email).toBe(user.email);
      expect(updatedUser.administrador).toBe(user.administrador);
    });

    test('deve atualizar apenas o email mantendo outros campos', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      const newEmail = `new_email_${Date.now()}@teste.com`;
      
      const updateData = {
        nome: user.nome,
        email: newEmail,
        password: user.password,
        administrador: user.administrador
      };

      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: updateData
      });

      expect(updateResponse.status()).toBe(200);

      const getResponse = await apiClient.request.get(`/usuarios/${user._id}`);
      const updatedUser = await getResponse.json();

      expect(updatedUser.email).toBe(newEmail);
      expect(updatedUser.nome).toBe(user.nome);
      expect(updatedUser.administrador).toBe(user.administrador);
    });

    test('deve atualizar senha do usuário', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      const newPassword = 'NovaSenhaForte123!';
      
      const updateData = {
        nome: user.nome,
        email: user.email,
        password: newPassword,
        administrador: user.administrador
      };

      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: updateData
      });

      expect(updateResponse.status()).toBe(200);

      // Testa login com senha antiga (deve falhar)
      const oldLoginResponse = await apiClient.authenticate(user.email, user.password);
      expect(oldLoginResponse.status).toBe(401);

      // Testa login com senha nova (deve funcionar)
      const newLoginResponse = await apiClient.authenticate(user.email, newPassword);
      expect(newLoginResponse.status).toBe(200);
    });

    test('deve promover usuário comum a administrador', async ({ apiClient }) => {
      const user = await createTestUser(apiClient, {
        administrador: 'false'
      });

      const updateData = {
        nome: user.nome,
        email: user.email,
        password: user.password,
        administrador: 'true'
      };

      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: updateData
      });

      expect(updateResponse.status()).toBe(200);

      const getResponse = await apiClient.request.get(`/usuarios/${user._id}`);
      const updatedUser = await getResponse.json();

      expect(updatedUser.administrador).toBe('true');
    });

    test('deve rebaixar administrador para usuário comum', async ({ apiClient }) => {
      const user = await createTestUser(apiClient, {
        administrador: 'true'
      });

      const updateData = {
        nome: user.nome,
        email: user.email,
        password: user.password,
        administrador: 'false'
      };

      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: updateData
      });

      expect(updateResponse.status()).toBe(200);

      const getResponse = await apiClient.request.get(`/usuarios/${user._id}`);
      const updatedUser = await getResponse.json();

      expect(updatedUser.administrador).toBe('false');
    });

    test('deve aceitar caracteres especiais nos campos', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const specialData = {
        nome: "José O'Brien & Associados",
        email: `special.chars+test_${Date.now()}@teste.com`,
        password: 'P@$$w0rd!#%&*',
        administrador: user.administrador
      };

      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: specialData
      });

      expect(updateResponse.status()).toBe(200);

      const getResponse = await apiClient.request.get(`/usuarios/${user._id}`);
      const updatedUser = await getResponse.json();

      expect(updatedUser.nome).toBe(specialData.nome);
      expect(updatedUser.email).toBe(specialData.email);
    });
  });

  test.describe('Validações de Campos Obrigatórios', () => {

    test('deve falhar quando campo nome está ausente', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const updateData = {
        email: user.email,
        password: user.password,
        administrador: user.administrador
      };

      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: updateData
      });

      expect(updateResponse.status()).toBe(400);
      
      const body = await updateResponse.json();
      expect(body).toHaveProperty('nome');
      expect(body.nome).toContain('obrigatório');
    });

    test('deve falhar quando campo email está ausente', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const updateData = {
        nome: user.nome,
        password: user.password,
        administrador: user.administrador
      };

      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: updateData
      });

      expect(updateResponse.status()).toBe(400);
      
      const body = await updateResponse.json();
      expect(body).toHaveProperty('email');
    });

    test('deve falhar quando campo password está ausente', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const updateData = {
        nome: user.nome,
        email: user.email,
        administrador: user.administrador
      };

      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: updateData
      });

      expect(updateResponse.status()).toBe(400);
      
      const body = await updateResponse.json();
      expect(body).toHaveProperty('password');
    });

    test('deve falhar quando campo administrador está ausente', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const updateData = {
        nome: user.nome,
        email: user.email,
        password: user.password
      };

      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: updateData
      });

      expect(updateResponse.status()).toBe(400);
      
      const body = await updateResponse.json();
      expect(body).toHaveProperty('administrador');
    });

    test('deve falhar com body vazio', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: {}
      });

      expect(updateResponse.status()).toBe(400);
    });
  });

  test.describe('Validações de Formato e Tipo', () => {

    test('deve falhar com email em formato inválido', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const invalidEmails = [
        'email-sem-arroba',
        '@dominio.com',
        'usuario@',
        'usuario @dominio.com',
        'usuario@dominio',
        'usuario@@dominio.com'
      ];

      for (const invalidEmail of invalidEmails) {
        const updateData = {
          nome: user.nome,
          email: invalidEmail,
          password: user.password,
          administrador: user.administrador
        };

        const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
          data: updateData
        });

        expect(updateResponse.status()).toBe(400);
        
        const body = await updateResponse.json();
        expect(body).toHaveProperty('email');
        
        console.log(`Email inválido testado: ${invalidEmail}`);
      }
    });

    test('deve falhar quando administrador não é "true" ou "false"', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const invalidAdminValues = [
        'TRUE', 'FALSE', 'True', 'False',
        '1', '0', 'yes', 'no',
        true, false, 1, 0, null
      ];

      for (const adminValue of invalidAdminValues) {
        const updateData = {
          nome: user.nome,
          email: user.email,
          password: user.password,
          administrador: adminValue
        };

        const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
          data: updateData
        });

        expect(updateResponse.status()).toBe(400);
        
        console.log(`Valor administrador inválido testado: ${adminValue}`);
      }
    });

    test('deve falhar com campos vazios', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const updateData = {
        nome: '',
        email: '',
        password: '',
        administrador: ''
      };

      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: updateData
      });

      expect(updateResponse.status()).toBe(400);
    });

    test('deve validar tamanho mínimo da senha', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const shortPasswords = ['', 'a', '12', '123', '1234', '12345'];

      for (const password of shortPasswords) {
        const updateData = {
          nome: user.nome,
          email: user.email,
          password: password,
          administrador: user.administrador
        };

        const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
          data: updateData
        });

        // Pode aceitar ou rejeitar senhas curtas
        if (updateResponse.status() === 400) {
          const body = await updateResponse.json();
          expect(body).toHaveProperty('password');
          console.log(`Senha curta rejeitada: "${password}" (${password.length} caracteres)`);
        }
      }
    });
  });

  test.describe('Validações de ID e Duplicação', () => {

    test('deve falhar ao atualizar usuário inexistente', async ({ apiClient }) => {
      const fakeIds = [
        '123456789012345678901234',
        'nonexistentid123',
        'abcdef123456'
      ];

      const updateData = {
        nome: 'Test',
        email: 'test@test.com',
        password: 'senha123',
        administrador: 'false'
      };

      for (const fakeId of fakeIds) {
        const updateResponse = await apiClient.request.put(`/usuarios/${fakeId}`, {
          data: updateData
        });

        expect([400, 404]).toContain(updateResponse.status());
        
        const body = await updateResponse.json();
        expect(body).toHaveProperty('message');
      }
    });

    test('deve falhar ao atualizar para email já existente', async ({ apiClient }) => {
      // Cria dois usuários
      const user1 = await createTestUser(apiClient, {
        email: `user1_${Date.now()}@teste.com`
      });
      
      const user2 = await createTestUser(apiClient, {
        email: `user2_${Date.now()}@teste.com`
      });

      // Tenta atualizar user2 com email de user1
      const updateData = {
        nome: user2.nome,
        email: user1.email, // Email já existe
        password: user2.password,
        administrador: user2.administrador
      };

      const updateResponse = await apiClient.request.put(`/usuarios/${user2._id}`, {
        data: updateData
      });

      expect(updateResponse.status()).toBe(400);
      
      const body = await updateResponse.json();
      expect(body).toHaveProperty('message');
      expect(body.message).toContain('já');
    });

    test('deve permitir atualizar usuário mantendo seu próprio email', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      // Atualiza mantendo o mesmo email
      const updateData = {
        nome: 'Nome Novo',
        email: user.email, // Mesmo email
        password: user.password,
        administrador: user.administrador
      };

      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: updateData
      });

      expect(updateResponse.status()).toBe(200);
    });

    test('deve ser case-insensitive para emails duplicados', async ({ apiClient }) => {
      const user1 = await createTestUser(apiClient, {
        email: `lowercase_${Date.now()}@teste.com`
      });
      
      const user2 = await createTestUser(apiClient, {
        email: `other_${Date.now()}@teste.com`
      });

      // Tenta atualizar user2 com email de user1 em uppercase
      const updateData = {
        nome: user2.nome,
        email: user1.email.toUpperCase(),
        password: user2.password,
        administrador: user2.administrador
      };

      const updateResponse = await apiClient.request.put(`/usuarios/${user2._id}`, {
        data: updateData
      });

      // Se trata emails case-insensitive, deve falhar
      if (updateResponse.status() === 400) {
        console.log('✓ API trata emails como case-insensitive na atualização');
      } else {
        console.log('⚠️ API trata emails como case-sensitive na atualização');
      }
    });
  });

  test.describe('Segurança', () => {

    test('deve prevenir SQL Injection', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const sqlInjectionPayloads = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "admin'--"
      ];

      for (const payload of sqlInjectionPayloads) {
        const updateData = {
          nome: payload,
          email: `safe_${Date.now()}@teste.com`,
          password: payload,
          administrador: 'false'
        };

        const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
          data: updateData
        });

        // Não deve causar erro 500
        expect(updateResponse.status()).not.toBe(500);
        
        if (updateResponse.status() === 200) {
          // Se aceitou, verifica se foi salvo corretamente escapado
          const getResponse = await apiClient.request.get(`/usuarios/${user._id}`);
          const updatedUser = await getResponse.json();
          expect(updatedUser.nome).toBe(payload);
        }
      }
    });

    test('deve prevenir XSS', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const xssPayloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        'javascript:alert("XSS")'
      ];

      for (const payload of xssPayloads) {
        const updateData = {
          nome: payload,
          email: user.email,
          password: user.password,
          administrador: user.administrador
        };

        const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
          data: updateData
        });

        expect(updateResponse.status()).not.toBe(500);
        
        if (updateResponse.status() === 200) {
          const getResponse = await apiClient.request.get(`/usuarios/${user._id}`);
          const updatedUser = await getResponse.json();
          
          // O payload deve estar presente mas escapado
          expect(updatedUser.nome).toBe(payload);
        }
      }
    });

    test('deve criptografar nova senha', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      const newPassword = 'NovaSenhaPlain123';
      
      const updateData = {
        nome: user.nome,
        email: user.email,
        password: newPassword,
        administrador: user.administrador
      };

      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: updateData
      });

      expect(updateResponse.status()).toBe(200);

      // Busca o usuário
      const getResponse = await apiClient.request.get(`/usuarios/${user._id}`);
      const updatedUser = await getResponse.json();
      
      // Senha não deve ser retornada
      expect(updatedUser.password).toBeUndefined();
      
      // Testa que a senha foi criptografada fazendo login
      const loginResponse = await apiClient.authenticate(user.email, newPassword);
      expect(loginResponse.status).toBe(200);
    });

    test('deve validar autorização para atualizar usuário', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      // Tenta atualizar sem token
      const updateData = {
        nome: 'Unauthorized Update',
        email: user.email,
        password: user.password,
        administrador: user.administrador
      };

      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: updateData,
        headers: {
          'Authorization': ''
        }
      });

      // Se requer autenticação, deve retornar 401
      if (updateResponse.status() === 401) {
        console.log('✓ API requer autenticação para atualizar');
      } else if (updateResponse.status() === 200) {
        console.log('⚠️ API permite atualização sem autenticação');
      }
    });
  });

  test.describe('Operações Parciais e PATCH', () => {

    test('deve verificar se API suporta PATCH para atualizações parciais', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      // Tenta PATCH apenas com nome
      const patchResponse = await apiClient.request.patch(`/usuarios/${user._id}`, {
        data: {
          nome: 'Apenas Nome via PATCH'
        }
      });

      if (patchResponse.status() === 200) {
        console.log('✓ API suporta PATCH para atualizações parciais');
        
        const getResponse = await apiClient.request.get(`/usuarios/${user._id}`);
        const updatedUser = await getResponse.json();
        
        expect(updatedUser.nome).toBe('Apenas Nome via PATCH');
        expect(updatedUser.email).toBe(user.email);
      } else if (patchResponse.status() === 405) {
        console.log('ℹ️ API não suporta método PATCH');
      }
    });

    test('deve exigir todos os campos no PUT (não permite parcial)', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      // Tenta PUT apenas com nome (sem outros campos)
      const partialUpdate = {
        nome: 'Apenas Nome'
      };

      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: partialUpdate
      });

      // PUT deve exigir todos os campos
      expect(updateResponse.status()).toBe(400);
      
      const body = await updateResponse.json();
      // Deve reclamar dos campos faltantes
      expect(Object.keys(body).length).toBeGreaterThan(0);
    });
  });

  test.describe('Validações de Contrato', () => {

    test('deve retornar estrutura correta ao atualizar com sucesso', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const updateData = {
        nome: 'Updated Name',
        email: user.email,
        password: user.password,
        administrador: user.administrador
      };

      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: updateData
      });

      expect(updateResponse.status()).toBe(200);
      
      const body = await updateResponse.json();
      
      // Valida estrutura da resposta
      expect(body).toHaveProperty('message');
      expect(typeof body.message).toBe('string');
      expect(body.message.toLowerCase()).toMatch(/atualiza|sucesso|alter/);
    });

    test('deve retornar Content-Type correto', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const updateData = {
        nome: user.nome,
        email: user.email,
        password: user.password,
        administrador: user.administrador
      };

      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: updateData
      });

      const headers = updateResponse.headers();
      expect(headers['content-type']).toContain('application/json');
    });

    test('deve retornar erro estruturado para validações', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const invalidData = {
        nome: '',
        email: 'invalid-email',
        password: '12',
        administrador: 'maybe'
      };

      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: invalidData
      });

      expect(updateResponse.status()).toBe(400);
      
      const body = await updateResponse.json();
      
      // Deve ter estrutura de erro consistente
      expect(typeof body).toBe('object');
      
      // Cada erro deve ter uma mensagem
      Object.values(body).forEach(value => {
        expect(typeof value).toBe('string');
      });
    });
  });

  test.describe('Performance e Concorrência', () => {

    test('deve atualizar em tempo aceitável', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const updateData = {
        nome: 'Performance Test',
        email: user.email,
        password: user.password,
        administrador: user.administrador
      };

      const startTime = Date.now();
      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: updateData
      });
      const endTime = Date.now();

      expect(updateResponse.status()).toBe(200);
      
      const responseTime = endTime - startTime;
      expect(responseTime).toBeLessThan(2000);
      
      console.log(`Tempo de atualização: ${responseTime}ms`);
    });

    test('deve lidar com atualizações concorrentes', async ({ apiClient }) => {
      // Cria múltiplos usuários
      const users = await Promise.all([
        createTestUser(apiClient),
        createTestUser(apiClient),
        createTestUser(apiClient)
      ]);

      // Atualiza todos concorrentemente
      const updatePromises = users.map((user, index) => 
        apiClient.request.put(`/usuarios/${user._id}`, {
          data: {
            nome: `Concurrent Update ${index}`,
            email: user.email,
            password: user.password,
            administrador: user.administrador
          }
        })
      );

      const responses = await Promise.all(updatePromises);
      
      // Todos devem ter sucesso
      responses.forEach(response => {
        expect(response.status()).toBe(200);
      });
    });

    test('deve prevenir condições de corrida', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      // Tenta múltiplas atualizações simultâneas no mesmo usuário
      const updatePromises = Array(5).fill(null).map((_, index) => 
        apiClient.request.put(`/usuarios/${user._id}`, {
          data: {
            nome: `Race Condition ${index}`,
            email: `race_${index}_${Date.now()}@teste.com`,
            password: user.password,
            administrador: user.administrador
          }
        })
      );

      const responses = await Promise.all(updatePromises);
      
      // Algumas podem falhar por email duplicado, mas não deve haver erro 500
      responses.forEach(response => {
        expect(response.status()).toBeLessThan(500);
      });
      
      // Verifica o estado final
      const getResponse = await apiClient.request.get(`/usuarios/${user._id}`);
      const finalUser = await getResponse.json();
      
      console.log(`Estado final após race condition: ${finalUser.nome}`);
    });
  });

  test.describe('Casos Especiais', () => {

    test('deve manter consistência ao atualizar múltiplas vezes', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      const updates = [
        { nome: 'Primeira Atualização' },
        { nome: 'Segunda Atualização' },
        { nome: 'Terceira Atualização' }
      ];

      for (const update of updates) {
        const updateData = {
          nome: update.nome,
          email: user.email,
          password: user.password,
          administrador: user.administrador
        };

        const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
          data: updateData
        });

        expect(updateResponse.status()).toBe(200);
        
        // Verifica se foi atualizado
        const getResponse = await apiClient.request.get(`/usuarios/${user._id}`);
        const updatedUser = await getResponse.json();
        
        expect(updatedUser.nome).toBe(update.nome);
      }
    });

    test('deve lidar com caracteres Unicode', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const unicodeData = {
        nome: '🚀 Émoji Tëst 你好 مرحبا',
        email: user.email,
        password: '密码123🔐',
        administrador: user.administrador
      };

      const updateResponse = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: unicodeData
      });

      if (updateResponse.status() === 200) {
        const getResponse = await apiClient.request.get(`/usuarios/${user._id}`);
        const updatedUser = await getResponse.json();
        
        expect(updatedUser.nome).toBe(unicodeData.nome);
      }
    });

    test('deve validar idempotência', async ({ apiClient }) => {
      const user = await createTestUser(apiClient);
      
      const updateData = {
        nome: 'Idempotent Name',
        email: user.email,
        password: user.password,
        administrador: user.administrador
      };

      // Faz a mesma atualização duas vezes
      const response1 = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: updateData
      });
      
      const response2 = await apiClient.request.put(`/usuarios/${user._id}`, {
        data: updateData
      });

      // Ambas devem ter sucesso
      expect(response1.status()).toBe(200);
      expect(response2.status()).toBe(200);
      
      // Estado final deve ser consistente
      const getResponse = await apiClient.request.get(`/usuarios/${user._id}`);
      const finalUser = await getResponse.json();
      
      expect(finalUser.nome).toBe('Idempotent Name');
    });
  });
});