import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  // Diretório onde estão os testes
  testDir: './tests',
  
  // Padrão para encontrar arquivos de teste
  testMatch: '**/*.spec.ts',
  
  // Tempo máximo para cada teste
  timeout: 30000,
  
  // Configuração de retry
  retries: process.env.CI ? 2 : 0,
  
  // Número de workers paralelos
  workers: process.env.CI ? 1 : undefined,
  
  // Reporter configuration
  reporter: process.env.CI 
    ? [
        ['list'],
        ['html', { outputFolder: 'playwright-report', open: 'never' }],
        ['json', { outputFile: 'test-results/results.json' }],
        ['junit', { outputFile: 'test-results/junit.xml' }]
      ]
    : [
        ['list'],
        ['html', { outputFolder: 'playwright-report', open: 'on-failure' }]
      ],
  
  // Configuração global
  use: {
    // URL base da API
    baseURL: process.env.API_BASE_URL || 'https://serverest.dev',
    
    // Não usa navegador para testes de API
    headless: true,
    
    // Trace para debugging
    trace: 'on-first-retry',
    
    // Headers padrão
    extraHTTPHeaders: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
    
    // Timeout para requisições
    actionTimeout: 10000,
    
    // Ignora erros HTTPS
    ignoreHTTPSErrors: true,
  },
  
  // Configuração de saída
  outputDir: 'test-results/',
  
  // Configuração para CI/CD
  forbidOnly: !!process.env.CI,
  
  // Configuração de projetos (diferentes configurações de teste)
  projects: [
    {
      name: 'api-tests',
      testDir: './tests',
      use: {
        ...devices['Desktop Chrome'],
      },
    },
  ],
  
  // Removido temporariamente até criarmos os arquivos
  // globalSetup: './utils/global-setup.ts',
  // globalTeardown: './utils/global-teardown.ts',
});