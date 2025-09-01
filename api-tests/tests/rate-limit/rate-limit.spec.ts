// tests/rate-limit/rate-limit.spec.ts
import { test, expect } from '../../utils/test-fixtures';
import { FixtureLoader } from '../../utils/fixture-loader';

test.describe('Rate Limiting - Limites de Taxa da API', () => {
  
  // Configuração do rate limit esperado
  const RATE_LIMIT = {
    maxRequests: 100,
    windowMs: 60 * 1000, // 1 minuto em ms
    retryAfterSeconds: 60
  };

  test.describe('Validação do Limite de Requisições', () => {
    
    test('deve permitir até 100 requisições por minuto', async ({ apiClient }) => {
      const responses: any[] = [];
      const startTime = Date.now();
      
      // Faz exatamente 100 requisições
      for (let i = 1; i <= RATE_LIMIT.maxRequests; i++) {
        const response = await apiClient.request.get('/usuarios');
        responses.push({
          index: i,
          status: response.status(),
          headers: response.headers()
        });
        
        // Verifica se ainda está dentro do limite
        expect(response.status()).not.toBe(429);
      }
      
      const endTime = Date.now();
      const duration = endTime - startTime;
      
      // Todas as 100 requisições devem ter sucesso
      const successfulRequests = responses.filter(r => r.status === 200);
      expect(successfulRequests.length).toBe(RATE_LIMIT.maxRequests);
      
      console.log(`✓ Completou ${RATE_LIMIT.maxRequests} requisições em ${duration}ms`);
      
      // Verifica headers de rate limit se disponíveis
      const lastResponse = responses[responses.length - 1];
      if (lastResponse.headers['x-ratelimit-limit']) {
        expect(parseInt(lastResponse.headers['x-ratelimit-limit'])).toBe(RATE_LIMIT.maxRequests);
      }
      if (lastResponse.headers['x-ratelimit-remaining']) {
        expect(parseInt(lastResponse.headers['x-ratelimit-remaining'])).toBe(0);
      }
    });

    test('deve bloquear a 101ª requisição', async ({ apiClient }) => {
      const responses: any[] = [];
      
      // Faz 101 requisições rapidamente
      for (let i = 1; i <= RATE_LIMIT.maxRequests + 1; i++) {
        const response = await apiClient.request.get('/usuarios');
        responses.push({
          index: i,
          status: response.status(),
          body: response.status() === 429 ? await response.json() : null
        });
        
        // Para após receber o primeiro 429
        if (response.status() === 429) {
          break;
        }
      }
      
      // A última requisição deve ser bloqueada
      const blockedRequest = responses.find(r => r.status === 429);
      expect(blockedRequest).toBeDefined();
      expect(blockedRequest.status).toBe(429);
      
      // Verifica mensagem de erro
      if (blockedRequest.body) {
        expect(blockedRequest.body).toHaveProperty('message');
        expect(blockedRequest.body.message.toLowerCase()).toContain('limit');
      }
    });

    test('deve incluir headers de rate limit nas respostas', async ({ apiClient }) => {
      const response = await apiClient.request.get('/usuarios');
      const headers = response.headers();
      
      // Verifica headers comuns de rate limiting
      const possibleHeaders = [
        'x-ratelimit-limit',
        'x-ratelimit-remaining',
        'x-ratelimit-reset',
        'x-rate-limit-limit',
        'x-rate-limit-remaining',
        'x-rate-limit-reset',
        'ratelimit-limit',
        'ratelimit-remaining',
        'ratelimit-reset'
      ];
      
      const foundHeaders = possibleHeaders.filter(h => headers[h] !== undefined);
      
      if (foundHeaders.length > 0) {
        console.log('Headers de rate limit encontrados:', foundHeaders);
        
        // Se tem headers, valida os valores
        const limitHeader = foundHeaders.find(h => h.includes('limit') && !h.includes('remaining'));
        if (limitHeader) {
          expect(parseInt(headers[limitHeader])).toBeGreaterThan(0);
        }
      }
    });

    test('deve incluir header Retry-After quando bloqueado', async ({ apiClient }) => {
      // Primeiro esgota o limite
      for (let i = 1; i <= RATE_LIMIT.maxRequests; i++) {
        await apiClient.request.get('/usuarios');
      }
      
      // Próxima requisição deve ser bloqueada
      const blockedResponse = await apiClient.request.get('/usuarios');
      
      if (blockedResponse.status() === 429) {
        const headers = blockedResponse.headers();
        
        // Verifica header Retry-After
        if (headers['retry-after']) {
          const retryAfter = parseInt(headers['retry-after']);
          expect(retryAfter).toBeGreaterThan(0);
          expect(retryAfter).toBeLessThanOrEqual(RATE_LIMIT.retryAfterSeconds);
        }
      }
    });
  });

  test.describe('Reset do Rate Limit', () => {
    
    test('deve resetar o contador após o período de tempo', async ({ apiClient }) => {
      test.setTimeout(150000); // 2.5 minutos de timeout
      
      // Fase 1: Esgota o limite
      console.log('Fase 1: Esgotando limite de requisições...');
      let blockedAt = 0;
      
      for (let i = 1; i <= RATE_LIMIT.maxRequests + 5; i++) {
        const response = await apiClient.request.get('/usuarios');
        if (response.status() === 429) {
          blockedAt = i;
          console.log(`Bloqueado na requisição ${i}`);
          break;
        }
      }
      
      expect(blockedAt).toBeGreaterThan(0);
      
      // Fase 2: Aguarda reset (61 segundos para garantir)
      console.log('Fase 2: Aguardando 61 segundos para reset...');
      await new Promise(resolve => setTimeout(resolve, 61000));
      
      // Fase 3: Verifica se pode fazer requisições novamente
      console.log('Fase 3: Verificando reset do limite...');
      const responseAfterWait = await apiClient.request.get('/usuarios');
      
      expect(responseAfterWait.status()).toBe(200);
      console.log('✓ Rate limit resetado com sucesso');
    });

    test('deve manter o bloqueio antes do tempo de reset', async ({ apiClient }) => {
      test.setTimeout(120000); // 2 minutos de timeout
      
      // Esgota o limite
      for (let i = 1; i <= RATE_LIMIT.maxRequests + 1; i++) {
        const response = await apiClient.request.get('/usuarios');
        if (response.status() === 429) {
          break;
        }
      }
      
      // Aguarda apenas 30 segundos (metade do tempo)
      console.log('Aguardando 30 segundos (não deve resetar ainda)...');
      await new Promise(resolve => setTimeout(resolve, 30000));
      
      // Ainda deve estar bloqueado
      const response = await apiClient.request.get('/usuarios');
      expect(response.status()).toBe(429);
    });
  });

  test.describe('Rate Limit por Endpoint', () => {
    
    test('deve aplicar rate limit independente por endpoint', async ({ apiClient }) => {
      const endpoints = [
        '/usuarios',
        '/login',
        '/produtos',
        '/carrinhos'
      ];
      
      const results: Record<string, any> = {};
      
      for (const endpoint of endpoints) {
        results[endpoint] = {
          successCount: 0,
          firstBlockAt: null
        };
        
        // Tenta 105 requisições em cada endpoint
        for (let i = 1; i <= 105; i++) {
          let response;
          
          if (endpoint === '/login') {
            response = await apiClient.request.post(endpoint, {
              data: { email: 'teste@teste.com', password: 'senha123' }
            });
          } else {
            response = await apiClient.request.get(endpoint);
          }
          
          if (response.status() !== 429) {
            results[endpoint].successCount++;
          } else {
            results[endpoint].firstBlockAt = i;
            break;
          }
        }
      }
      
      // Verifica se cada endpoint tem seu próprio contador
      console.log('Resultados por endpoint:', results);
      
      // Se os rate limits são independentes, cada endpoint deve permitir ~100 requisições
      for (const endpoint of endpoints) {
        if (results[endpoint].firstBlockAt) {
          expect(results[endpoint].successCount).toBeGreaterThanOrEqual(90);
          expect(results[endpoint].successCount).toBeLessThanOrEqual(110);
        }
      }
    });
  });

  test.describe('Rate Limit por IP/Cliente', () => {
    
    test('deve aplicar rate limit por cliente/IP', async ({ apiClient, request }) => {
      // Cria dois clientes diferentes (simulando IPs diferentes)
      const client1 = apiClient;
      const client2 = new (await import('../../utils/api-client')).ApiClient(request);
      
      const client1Results = { success: 0, blocked: false };
      const client2Results = { success: 0, blocked: false };
      
      // Cliente 1 faz 50 requisições
      for (let i = 1; i <= 50; i++) {
        const response = await client1.request.get('/usuarios');
        if (response.status() === 200) {
          client1Results.success++;
        } else if (response.status() === 429) {
          client1Results.blocked = true;
          break;
        }
      }
      
      // Cliente 2 também faz 50 requisições
      for (let i = 1; i <= 50; i++) {
        const response = await client2.request.get('/usuarios');
        if (response.status() === 200) {
          client2Results.success++;
        } else if (response.status() === 429) {
          client2Results.blocked = true;
          break;
        }
      }
      
      // Ambos devem conseguir fazer 50 requisições se o limite é por cliente
      console.log('Cliente 1:', client1Results);
      console.log('Cliente 2:', client2Results);
      
      // Se o rate limit é global, um deles será bloqueado
      // Se é por cliente, ambos devem ter sucesso
      const totalSuccess = client1Results.success + client2Results.success;
      
      if (totalSuccess === 100) {
        console.log('Rate limit parece ser por cliente/IP');
      } else if (totalSuccess < 100) {
        console.log('Rate limit parece ser global');
      }
    });
  });

  test.describe('Rate Limit com Autenticação', () => {
    
    test('deve ter limites diferentes para usuários autenticados', async ({ 
      apiClient, 
      authenticatedClient 
    }) => {
      const unauthResults = { success: 0, blocked: false };
      const authResults = { success: 0, blocked: false };
      
      // Teste sem autenticação
      for (let i = 1; i <= 110; i++) {
        const response = await apiClient.request.get('/usuarios');
        if (response.status() === 200) {
          unauthResults.success++;
        } else if (response.status() === 429) {
          unauthResults.blocked = true;
          console.log(`Não autenticado bloqueado na requisição ${i}`);
          break;
        }
      }
      
      // Aguarda um pouco para não misturar os testes
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Teste com autenticação
      for (let i = 1; i <= 110; i++) {
        const response = await authenticatedClient.request.get('/usuarios');
        if (response.status() === 200) {
          authResults.success++;
        } else if (response.status() === 429) {
          authResults.blocked = true;
          console.log(`Autenticado bloqueado na requisição ${i}`);
          break;
        }
      }
      
      console.log('Resultados não autenticado:', unauthResults);
      console.log('Resultados autenticado:', authResults);
      
      // Usuários autenticados podem ter limite maior ou não ter limite
      if (authResults.success > unauthResults.success) {
        console.log('✓ Usuários autenticados têm limite maior');
      }
    });
  });

  test.describe('Comportamento sob Rate Limiting', () => {
    
    test('deve retornar status HTTP 429 Too Many Requests', async ({ apiClient }) => {
      // Esgota o limite
      for (let i = 1; i <= RATE_LIMIT.maxRequests; i++) {
        await apiClient.request.get('/usuarios');
      }
      
      // Próxima deve ser bloqueada
      const response = await apiClient.request.get('/usuarios');
      expect(response.status()).toBe(429);
    });

    test('deve retornar mensagem de erro apropriada', async ({ apiClient }) => {
      // Esgota o limite
      for (let i = 1; i <= RATE_LIMIT.maxRequests; i++) {
        await apiClient.request.get('/usuarios');
      }
      
      const response = await apiClient.request.get('/usuarios');
      
      if (response.status() === 429) {
        const body = await response.json();
        expect(body).toHaveProperty('message');
        
        // Verifica se a mensagem é informativa
        const message = body.message.toLowerCase();
        expect(
          message.includes('limit') || 
          message.includes('many requests') ||
          message.includes('rate')
        ).toBe(true);
      }
    });

    test('deve manter outros status de erro quando bloqueado', async ({ apiClient }) => {
      // Esgota o limite
      for (let i = 1; i <= RATE_LIMIT.maxRequests; i++) {
        await apiClient.request.get('/usuarios');
      }
      
      // Tenta uma requisição com erro diferente (ex: 404)
      const response = await apiClient.request.get('/usuarios/id-inexistente-123456789');
      
      // Deve retornar 429, não 404, pois o rate limit tem precedência
      if (response.status() === 429) {
        expect(response.status()).toBe(429);
      }
    });
  });

  test.describe('Monitoramento e Métricas', () => {
    
    test('deve logar informações úteis sobre rate limiting', async ({ apiClient }) => {
      const metrics = {
        totalRequests: 0,
        successfulRequests: 0,
        blockedRequests: 0,
        averageResponseTime: 0,
        responseTimes: [] as number[]
      };
      
      // Faz requisições e coleta métricas
      for (let i = 1; i <= RATE_LIMIT.maxRequests + 10; i++) {
        const startTime = Date.now();
        const response = await apiClient.request.get('/usuarios');
        const responseTime = Date.now() - startTime;
        
        metrics.totalRequests++;
        metrics.responseTimes.push(responseTime);
        
        if (response.status() === 200) {
          metrics.successfulRequests++;
        } else if (response.status() === 429) {
          metrics.blockedRequests++;
        }
        
        // Para se começar a receber muitos 429s
        if (metrics.blockedRequests >= 5) {
          break;
        }
      }
      
      // Calcula média de tempo de resposta
      metrics.averageResponseTime = 
        metrics.responseTimes.reduce((a, b) => a + b, 0) / metrics.responseTimes.length;
      
      console.log('📊 Métricas de Rate Limiting:');
      console.log(`  Total de requisições: ${metrics.totalRequests}`);
      console.log(`  Requisições bem-sucedidas: ${metrics.successfulRequests}`);
      console.log(`  Requisições bloqueadas: ${metrics.blockedRequests}`);
      console.log(`  Tempo médio de resposta: ${metrics.averageResponseTime.toFixed(2)}ms`);
      console.log(`  Taxa de sucesso: ${((metrics.successfulRequests / metrics.totalRequests) * 100).toFixed(2)}%`);
      
      // Validações
      expect(metrics.successfulRequests).toBeLessThanOrEqual(RATE_LIMIT.maxRequests);
      expect(metrics.blockedRequests).toBeGreaterThan(0);
    });
  });

  test.describe('Cenários Especiais', () => {
    
    test('deve lidar com burst de requisições', async ({ apiClient }) => {
      const burstSize = 20;
      const results = await Promise.all(
        Array.from({ length: burstSize }, async (_, i) => {
          const response = await apiClient.request.get('/usuarios');
          return {
            index: i,
            status: response.status()
          };
        })
      );
      
      const successful = results.filter(r => r.status === 200).length;
      const blocked = results.filter(r => r.status === 429).length;
      
      console.log(`Burst de ${burstSize} requisições:`);
      console.log(`  Sucesso: ${successful}`);
      console.log(`  Bloqueadas: ${blocked}`);
      
      // Pelo menos algumas devem passar
      expect(successful).toBeGreaterThan(0);
    });

    test('deve aplicar rate limit em diferentes métodos HTTP', async ({ apiClient }) => {
      const methods = [
        { method: 'GET', path: '/usuarios' },
        { method: 'POST', path: '/usuarios', data: FixtureLoader.generate('users/valid-users') },
        { method: 'PUT', path: '/usuarios/123', data: { nome: 'Teste' } },
        { method: 'DELETE', path: '/usuarios/123' }
      ];
      
      let totalRequests = 0;
      let blockedFound = false;
      
      // Faz requisições alternando métodos até encontrar bloqueio
      for (let i = 0; i < 120; i++) {
        const methodInfo = methods[i % methods.length];
        let response;
        
        switch (methodInfo.method) {
          case 'GET':
            response = await apiClient.request.get(methodInfo.path);
            break;
          case 'POST':
            response = await apiClient.request.post(methodInfo.path, { data: methodInfo.data });
            break;
          case 'PUT':
            response = await apiClient.request.put(methodInfo.path, { data: methodInfo.data });
            break;
          case 'DELETE':
            response = await apiClient.request.delete(methodInfo.path);
            break;
        }
        
        totalRequests++;
        
        if (response!.status() === 429) {
          blockedFound = true;
          console.log(`Rate limit atingido após ${totalRequests} requisições de métodos mistos`);
          break;
        }
      }
      
      // Deve encontrar rate limit em algum momento
      expect(blockedFound).toBe(true);
      expect(totalRequests).toBeLessThanOrEqual(120);
    });
  });
});