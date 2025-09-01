import { test as base, APIRequestContext } from '@playwright/test';
import { FixtureLoader } from './fixture-loader';
import { ApiClient } from './api-client';

// Define os tipos das fixtures
type UserData = {
  nome: string;
  email: string;
  password: string;
  administrador: string;
};

type TestFixtures = {
  apiClient: ApiClient;
  validUsers: Record<string, UserData>;
  invalidUsers: Record<string, UserData>;
  testUser: UserData;
  authenticatedClient: ApiClient;
};

// Estende o test do Playwright com fixtures customizadas
export const test = base.extend<TestFixtures>({
  // Fixture para o cliente da API
  apiClient: async ({ request }, use) => {
    const client = new ApiClient(request);
    await use(client);
  },

  // Fixture para carregar usuários válidos
  validUsers: async ({}, use) => {
    const users = FixtureLoader.load<Record<string, UserData>>('users/valid-users');
    await use(users);
  },

  // Fixture para carregar usuários inválidos
  invalidUsers: async ({}, use) => {
    const users = FixtureLoader.load<Record<string, UserData>>('users/invalid-users');
    await use(users);
  },

  // Fixture para gerar um usuário de teste único
  testUser: async ({}, use) => {
    const timestamp = Date.now();
    const user: UserData = {
      nome: `Test User ${timestamp}`,
      email: `testuser_${timestamp}@teste.com`,
      password: 'senha123',
      administrador: 'false'
    };
    await use(user);
  },

  // Fixture para cliente autenticado
  authenticatedClient: async ({ apiClient, request }, use) => {
    // Primeiro cria um usuário admin para autenticação
    const adminData = FixtureLoader.generate<UserData>(
      'users/valid-users',
      { email: `admin_${Date.now()}@teste.com` }
    );

    await apiClient.createUser(adminData);
    const token = await apiClient.authenticate(adminData.email, adminData.password);
    
    // Cria um novo cliente com o token
    const authenticatedClient = new ApiClient(request, token);
    await use(authenticatedClient);

    // Cleanup: deletar o usuário criado
    // await apiClient.deleteUserByEmail(adminData.email);
  }
});

export { expect } from '@playwright/test';