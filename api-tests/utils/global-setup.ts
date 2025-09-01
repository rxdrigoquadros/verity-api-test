import { FullConfig } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

async function globalSetup(config: FullConfig) {
  console.log('\n🚀 Starting API Tests...\n');
  console.log(`📍 API Base URL: ${process.env.API_BASE_URL || 'https://serverest.dev'}`);
  console.log(`🔄 Retry Count: ${process.env.RETRY_COUNT || '2'}`);
  console.log(`⏱️  Timeout: ${process.env.API_TIMEOUT || '30000'}ms\n`);
  
  // Cria diretórios necessários
  const dirs = ['logs', 'test-results', 'test-data'];
  dirs.forEach(dir => {
    const dirPath = path.join(process.cwd(), dir);
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true });
      console.log(`📁 Created directory: ${dir}`);
    }
  });
  
  // Limpa logs antigos
  const logsDir = path.join(process.cwd(), 'logs');
  if (fs.existsSync(logsDir)) {
    const files = fs.readdirSync(logsDir);
    files.forEach(file => {
      if (file.endsWith('.log')) {
        fs.unlinkSync(path.join(logsDir, file));
      }
    });
    console.log('🧹 Cleaned old log files\n');
  }
  
  // Registra início dos testes
  const startTime = new Date().toISOString();
  process.env.TEST_START_TIME = startTime;
  
  console.log('✅ Global setup completed\n');
  console.log('─'.repeat(50) + '\n');
  
  return async () => {
    // Cleanup function that runs after all tests
  };
}

export default globalSetup;