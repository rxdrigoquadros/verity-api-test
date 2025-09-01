// utils/global-teardown.ts
import { FullConfig } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

async function globalTeardown(config: FullConfig) {
  console.log('\n' + '─'.repeat(50));
  console.log('\n🏁 Tests completed!\n');
  
  // Calcula duração total
  const startTime = process.env.TEST_START_TIME;
  if (startTime) {
    const duration = Date.now() - new Date(startTime).getTime();
    const seconds = Math.floor(duration / 1000);
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    
    console.log(`⏱️  Total duration: ${minutes}m ${remainingSeconds}s`);
  }
  
  // Gera resumo dos testes
  const resultsPath = path.join(process.cwd(), 'test-results', 'results.json');
  if (fs.existsSync(resultsPath)) {
    try {
      const results = JSON.parse(fs.readFileSync(resultsPath, 'utf-8'));
      console.log('\n📊 Test Summary:');
      console.log(`   ✅ Passed: ${results.stats?.passed || 0}`);
      console.log(`   ❌ Failed: ${results.stats?.failed || 0}`);
      console.log(`   ⏭️  Skipped: ${results.stats?.skipped || 0}`);
    } catch (error) {
      // Ignora erro se não conseguir ler o arquivo
    }
  }
  
  // Lista arquivos de report gerados
  const reportDir = path.join(process.cwd(), 'playwright-report');
  if (fs.existsSync(reportDir)) {
    console.log('\n📄 Reports generated:');
    console.log(`   - HTML Report: ${reportDir}/index.html`);
  }
  
  const logsDir = path.join(process.cwd(), 'logs');
  if (fs.existsSync(logsDir)) {
    const logFiles = fs.readdirSync(logsDir).filter(f => f.endsWith('.log'));
    if (logFiles.length > 0) {
      console.log(`   - Log files: ${logsDir}/`);
    }
  }
  
  console.log('\n✨ Global teardown completed\n');
}

export default globalTeardown;