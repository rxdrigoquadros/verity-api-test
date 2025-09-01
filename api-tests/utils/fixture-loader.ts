// utils/fixture-loader.ts
import * as fs from 'fs';
import * as path from 'path';

export class FixtureLoader {
  private static fixturesPath = path.join(process.cwd(), 'fixtures');

  /**
   * Carrega um arquivo JSON de fixture
   */
  static load<T>(fixturePath: string): T {
    const fullPath = path.join(this.fixturesPath, `${fixturePath}.json`);
    
    if (!fs.existsSync(fullPath)) {
      throw new Error(`Fixture não encontrada: ${fullPath}`);
    }

    const content = fs.readFileSync(fullPath, 'utf-8');
    return JSON.parse(content);
  }

  /**
   * Carrega e retorna um item específico de uma fixture
   */
  static loadItem<T>(fixturePath: string, itemKey: string): T {
    const data = this.load<any>(fixturePath);
    
    if (!data[itemKey]) {
      throw new Error(`Item '${itemKey}' não encontrado na fixture ${fixturePath}`);
    }

    return data[itemKey];
  }

  /**
   * Gera dados dinâmicos baseados em uma fixture
   */
  static generate<T>(fixturePath: string, overrides?: Partial<T>): T {
    const baseData = this.load<T>(fixturePath);
    
    // Adiciona timestamp para tornar emails únicos
    if (typeof baseData === 'object' && baseData !== null) {
      const data = { ...baseData } as any;
      
      if (data.email) {
        const timestamp = Date.now();
        data.email = data.email.replace('@', `_${timestamp}@`);
      }

      return { ...data, ...overrides } as T;
    }

    return baseData;
  }

  /**
   * Carrega múltiplas fixtures de uma vez
   */
  static loadMultiple<T extends Record<string, any>>(
    fixtures: string[]
  ): T {
    const result = {} as T;

    fixtures.forEach(fixturePath => {
      const key = path.basename(fixturePath);
      result[key] = this.load(fixturePath);
    });

    return result;
  }
}