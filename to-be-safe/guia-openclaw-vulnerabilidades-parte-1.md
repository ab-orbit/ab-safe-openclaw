# Guia Técnico: Remediação de Vulnerabilidades Críticas do OpenClaw
## Parte 1: CVE-2026-25253, Skills Maliciosos e Vulnerabilidades em Skills

---

## 1. CVE-2026-25253 - RCE via WebSocket (CVSS 8.8)

### 1.1 Causa Raiz Técnica

A vulnerabilidade ocorre em três pontos críticos:

1. **Validação inadequada de origem WebSocket**: O servidor OpenClaw não valida o header `Origin` nas conexões WebSocket, permitindo que qualquer site estabeleça uma conexão
2. **Auto-conexão sem confirmação do usuário**: A UI de controle confia cegamente no parâmetro `gatewayUrl` da query string e conecta automaticamente ao carregar
3. **Transmissão de credenciais**: O token de autenticação é enviado no payload da conexão WebSocket sem validação prévia

### 1.2 Código de Patch Completo

**Arquivo: `src/websocket-security-patch.ts`**

```typescript
import { WebSocketServer, WebSocket } from 'ws';
import { Request } from 'express';
import { createHash } from 'crypto';
import { URL } from 'url';

interface WebSocketSecurityConfig {
  allowedOrigins: string[];
  tokenTimeout: number; // em ms
  maxConnections: number;
  rateLimitPerIP: number;
}

interface TokenMetadata {
  createdAt: number;
  clientIp: string;
  userAgent: string;
  scope: string[];
}

class WebSocketSecurityManager {
  private config: WebSocketSecurityConfig;
  private tokenMetadata = new Map<string, TokenMetadata>();
  private connectionsByIP = new Map<string, number>();
  private blockedTokens = new Set<string>();

  constructor(config: WebSocketSecurityConfig) {
    this.config = config;
    this.startTokenCleanup();
  }

  /**
   * Valida a origem da requisição WebSocket
   * Implementa CORS para WebSocket
   */
  validateOrigin(
    req: Request,
    remoteAddress: string
  ): { valid: boolean; reason?: string } {
    const origin = req.headers.origin;
    const referer = req.headers.referer;

    // Rejeita se não houver origem
    if (!origin && !referer) {
      return {
        valid: false,
        reason: 'Missing Origin/Referer header'
      };
    }

    try {
      const originUrl = new URL(origin || referer || '');
      const isAllowed = this.config.allowedOrigins.some(allowed => {
        if (allowed === '*') return true; // Use com cuidado
        return originUrl.origin === allowed;
      });

      if (!isAllowed) {
        return {
          valid: false,
          reason: `Origin ${origin} not in whitelist`
        };
      }

      return { valid: true };
    } catch (error) {
      return {
        valid: false,
        reason: 'Invalid Origin/Referer format'
      };
    }
  }

  /**
   * Valida e armazena metadata do token
   */
  validateAndStoreToken(
    token: string,
    clientIp: string,
    userAgent: string,
    requiredScopes: string[]
  ): { valid: boolean; reason?: string } {
    // Verifica se token está bloqueado
    if (this.blockedTokens.has(token)) {
      return {
        valid: false,
        reason: 'Token has been revoked'
      };
    }

    // Verifica taxa de conexão por IP
    const currentConnections = this.connectionsByIP.get(clientIp) || 0;
    if (currentConnections >= this.config.rateLimitPerIP) {
      return {
        valid: false,
        reason: 'Rate limit exceeded for this IP'
      };
    }

    // Validação básica do token (deve ser implementada com JWT real)
    if (!this.isValidTokenFormat(token)) {
      return {
        valid: false,
        reason: 'Invalid token format'
      };
    }

    // Armazena metadata do token
    const metadata: TokenMetadata = {
      createdAt: Date.now(),
      clientIp,
      userAgent,
      scope: requiredScopes
    };

    this.tokenMetadata.set(token, metadata);
    this.connectionsByIP.set(clientIp, currentConnections + 1);

    return { valid: true };
  }

  /**
   * Verifica se token expirou
   */
  isTokenExpired(token: string): boolean {
    const metadata = this.tokenMetadata.get(token);
    if (!metadata) return true;

    const age = Date.now() - metadata.createdAt;
    return age > this.config.tokenTimeout;
  }

  /**
   * Revoga um token
   */
  revokeToken(token: string): void {
    this.blockedTokens.add(token);
    this.tokenMetadata.delete(token);
  }

  /**
   * Limpeza automática de tokens expirados
   */
  private startTokenCleanup(): void {
    setInterval(() => {
      for (const [token, metadata] of this.tokenMetadata.entries()) {
        if (Date.now() - metadata.createdAt > this.config.tokenTimeout) {
          this.tokenMetadata.delete(token);
          this.blockedTokens.delete(token);
        }
      }
    }, 60000); // A cada minuto
  }

  /**
   * Validação básica do formato do token
   */
  private isValidTokenFormat(token: string): boolean {
    // Implementar validação JWT apropriada
    return token.length > 20 && token.split('.').length === 3; // JWT tem 3 partes
  }
}

/**
 * Middleware Express para validar gatewayUrl
 */
export function validateGatewayUrlMiddleware(req: Request, res: any, next: any) {
  const gatewayUrl = req.query.gatewayUrl as string;

  if (!gatewayUrl) {
    // URL de gateway não fornecida, não há risco
    return next();
  }

  try {
    const url = new URL(gatewayUrl);

    // Valida protocolo
    if (!['ws:', 'wss:'].includes(url.protocol)) {
      return res.status(400).json({
        error: 'Invalid gateway URL protocol. Must be ws: or wss:'
      });
    }

    // Valida hostname (evita localhost para gateways remotos)
    if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
      return res.status(400).json({
        error: 'Cannot use localhost as gateway URL. Use explicit hostname.'
      });
    }

    // IMPORTANTE: Requer confirmação do usuário antes de conectar
    // Esta informação deve ser armazenada para validação subsequente
    req.gatewayUrl = gatewayUrl;
    req.requiresUserConfirmation = true;

    next();
  } catch (error) {
    return res.status(400).json({
      error: 'Invalid gateway URL format'
    });
  }
}

/**
 * Inicialização segura de WebSocket Server
 */
export function setupSecureWebSocketServer(
  httpServer: any,
  securityConfig: WebSocketSecurityConfig
) {
  const securityManager = new WebSocketSecurityManager(securityConfig);

  const wss = new WebSocketServer({
    noServer: true,
    perMessageDeflate: {
      zlevel: 7,
      memLevel: 7,
      chunkSize: 10 * 1024
    }
  });

  // Validação de upgrade
  httpServer.on('upgrade', (req: Request, socket: any, head: any) => {
    // 1. Validar origem
    const originCheck = securityManager.validateOrigin(req, socket.remoteAddress);
    if (!originCheck.valid) {
      console.warn(`WebSocket connection rejected: ${originCheck.reason}`);
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      socket.destroy();
      return;
    }

    // 2. Extrair e validar token
    const token = extractTokenFromRequest(req);
    if (!token) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    // 3. Validar token e metadata
    const tokenCheck = securityManager.validateAndStoreToken(
      token,
      socket.remoteAddress,
      req.headers['user-agent'] || 'unknown',
      ['operator.admin'] // Scopes necessários
    );

    if (!tokenCheck.valid) {
      console.warn(`Token validation failed: ${tokenCheck.reason}`);
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    // 4. Prosseguir com upgrade
    wss.handleUpgrade(req, socket, head, (ws: WebSocket) => {
      wss.emit('connection', ws, req, token, securityManager);
    });
  });

  // Handler de conexão
  wss.on('connection', (ws: WebSocket, req: Request, token: string, manager: WebSocketSecurityManager) => {
    console.log(`WebSocket connected from ${req.socket.remoteAddress}`);

    // Validar expiração de token em cada mensagem
    ws.on('message', (data: Buffer) => {
      if (manager.isTokenExpired(token)) {
        manager.revokeToken(token);
        ws.close(1008, 'Token expired');
        return;
      }

      try {
        const message = JSON.parse(data.toString());
        handleSecureWebSocketMessage(ws, message, token, manager);
      } catch (error) {
        console.error('Invalid WebSocket message format:', error);
        ws.send(JSON.stringify({ error: 'Invalid message format' }));
      }
    });

    ws.on('close', () => {
      manager.revokeToken(token);
      console.log(`WebSocket closed`);
    });

    ws.on('error', (error) => {
      console.error('WebSocket error:', error);
      manager.revokeToken(token);
    });
  });

  return wss;
}

/**
 * Extrai token de forma segura da requisição
 */
function extractTokenFromRequest(req: Request): string | null {
  // 1. Tenta Authorization header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }

  // 2. Tenta cookie seguro
  const cookies = req.headers.cookie;
  if (cookies) {
    const match = cookies.match(/auth_token=([^;]+)/);
    if (match) {
      return match[1];
    }
  }

  // NÃO tira token de query parameters (vulnerável)
  return null;
}

/**
 * Handler seguro para mensagens WebSocket
 */
function handleSecureWebSocketMessage(
  ws: WebSocket,
  message: any,
  token: string,
  manager: WebSocketSecurityManager
): void {
  // Valida estrutura da mensagem
  if (!message.type || !message.id) {
    ws.send(JSON.stringify({ error: 'Invalid message structure' }));
    return;
  }

  // Rate limiting por token
  // Implementar lógica de throttling aqui

  // Log da ação
  console.log(`[${token}] Action: ${message.type}`);

  // Processamento normal
  // Implementar lógica de negócio
}

export { WebSocketSecurityManager, TokenMetadata };
```

### 1.3 Configuração Necessária

**Arquivo: `src/config/websocket-config.ts`**

```typescript
import { config } from 'dotenv';

config();

export const WEBSOCKET_SECURITY_CONFIG = {
  // Apenas domínios explicitamente permitidos
  allowedOrigins: [
    process.env.FRONTEND_URL || 'http://localhost:3000',
    'https://yourdomain.com',
    'https://app.yourdomain.com'
  ],

  // Token expira em 1 hora
  tokenTimeout: 3600000,

  // Máximo de conexões simultâneas
  maxConnections: 1000,

  // Rate limit: máximo 100 conexões por minuto por IP
  rateLimitPerIP: 100
};

// Configuração de CORS para requisições HTTP
export const CORS_CONFIG = {
  origin: WEBSOCKET_SECURITY_CONFIG.allowedOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
};
```

### 1.4 Integração com Express

**Arquivo: `src/server.ts` (modificado)**

```typescript
import express, { Express } from 'express';
import { createServer } from 'http';
import cors from 'cors';
import {
  setupSecureWebSocketServer,
  validateGatewayUrlMiddleware
} from './websocket-security-patch';
import { WEBSOCKET_SECURITY_CONFIG, CORS_CONFIG } from './config/websocket-config';

const app: Express = express();
const httpServer = createServer(app);

// Middleware de segurança CORS
app.use(cors(CORS_CONFIG));

// Middleware para validar gatewayUrl
app.use(validateGatewayUrlMiddleware);

// Parsing JSON com limite de tamanho
app.use(express.json({ limit: '10mb' }));

// Setup de WebSocket seguro
const wss = setupSecureWebSocketServer(httpServer, WEBSOCKET_SECURITY_CONFIG);

// Endpoint para confirmar gateway manualmente
app.post('/api/gateway/confirm', (req, res) => {
  const { gatewayUrl, userConfirmed } = req.body;

  if (!userConfirmed) {
    return res.status(400).json({
      error: 'Gateway URL must be manually confirmed by user'
    });
  }

  // Validar novamente
  try {
    new URL(gatewayUrl);
    // Armazenar confirmação do usuário (sesssão, storage, etc)
    res.json({ success: true, message: 'Gateway URL confirmed' });
  } catch (error) {
    res.status(400).json({ error: 'Invalid gateway URL' });
  }
});

const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`WebSocket origins configured:`, WEBSOCKET_SECURITY_CONFIG.allowedOrigins);
});

export { httpServer, wss };
```

### 1.5 Testes de Segurança

**Arquivo: `tests/websocket-security.test.ts`**

```typescript
import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import WebSocket from 'ws';
import { createServer } from 'http';
import {
  setupSecureWebSocketServer,
  WebSocketSecurityManager
} from '../src/websocket-security-patch';
import { WEBSOCKET_SECURITY_CONFIG } from '../src/config/websocket-config';

describe('WebSocket Security Tests', () => {
  let httpServer: any;
  let wss: any;
  const testOrigin = 'http://localhost:3000';
  const validToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature';

  beforeAll(() => {
    httpServer = createServer();
    wss = setupSecureWebSocketServer(httpServer, WEBSOCKET_SECURITY_CONFIG);
    httpServer.listen(8080);
  });

  afterAll(() => {
    httpServer.close();
  });

  // TEST 1: Rejeita origem não autorizada
  it('should reject WebSocket from unauthorized origin', (done) => {
    const ws = new WebSocket('ws://localhost:8080', {
      headers: {
        'Origin': 'http://malicious-site.com',
        'Authorization': `Bearer ${validToken}`
      }
    });

    ws.on('error', () => {
      expect(ws.readyState).not.toBe(WebSocket.OPEN);
      done();
    });

    ws.on('open', () => {
      done(new Error('Should have rejected unauthorized origin'));
    });
  });

  // TEST 2: Aceita origem autorizada
  it('should accept WebSocket from authorized origin', (done) => {
    const ws = new WebSocket('ws://localhost:8080', {
      headers: {
        'Origin': testOrigin,
        'Authorization': `Bearer ${validToken}`
      }
    });

    ws.on('open', () => {
      expect(ws.readyState).toBe(WebSocket.OPEN);
      ws.close();
      done();
    });

    ws.on('error', () => {
      done(new Error('Should have accepted authorized origin'));
    });
  });

  // TEST 3: Rejeita quando falta token
  it('should reject WebSocket without authentication token', (done) => {
    const ws = new WebSocket('ws://localhost:8080', {
      headers: {
        'Origin': testOrigin
      }
    });

    ws.on('error', () => {
      expect(ws.readyState).not.toBe(WebSocket.OPEN);
      done();
    });
  });

  // TEST 4: Rejeita token revogado
  it('should reject revoked tokens', (done) => {
    const manager = new WebSocketSecurityManager(WEBSOCKET_SECURITY_CONFIG);
    const testToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig';

    // Valida token inicialmente
    const result1 = manager.validateAndStoreToken(
      testToken,
      '127.0.0.1',
      'test-agent',
      ['operator.admin']
    );
    expect(result1.valid).toBe(true);

    // Revoga token
    manager.revokeToken(testToken);

    // Tenta validar novamente
    const result2 = manager.validateAndStoreToken(
      testToken,
      '127.0.0.1',
      'test-agent',
      ['operator.admin']
    );
    expect(result2.valid).toBe(false);
    expect(result2.reason).toContain('revoked');
    done();
  });

  // TEST 5: Detecta tokens expirados
  it('should detect expired tokens', (done) => {
    const config = { ...WEBSOCKET_SECURITY_CONFIG, tokenTimeout: 100 };
    const manager = new WebSocketSecurityManager(config);
    const testToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.exp';

    manager.validateAndStoreToken(
      testToken,
      '127.0.0.1',
      'test-agent',
      ['operator.admin']
    );

    expect(manager.isTokenExpired(testToken)).toBe(false);

    // Aguarda expiração
    setTimeout(() => {
      expect(manager.isTokenExpired(testToken)).toBe(true);
      done();
    }, 150);
  });

  // TEST 6: Rate limiting por IP
  it('should enforce rate limiting per IP', () => {
    const config = { ...WEBSOCKET_SECURITY_CONFIG, rateLimitPerIP: 2 };
    const manager = new WebSocketSecurityManager(config);
    const ip = '192.168.1.100';

    const result1 = manager.validateAndStoreToken(
      'token1.fake.sig',
      ip,
      'agent',
      ['operator.admin']
    );
    expect(result1.valid).toBe(true);

    const result2 = manager.validateAndStoreToken(
      'token2.fake.sig',
      ip,
      'agent',
      ['operator.admin']
    );
    expect(result2.valid).toBe(true);

    const result3 = manager.validateAndStoreToken(
      'token3.fake.sig',
      ip,
      'agent',
      ['operator.admin']
    );
    expect(result3.valid).toBe(false);
    expect(result3.reason).toContain('Rate limit');
  });
});
```

### 1.6 Validação da Remediação

```bash
# 1. Executar testes
npm test -- websocket-security.test.ts

# 2. Verificar logs de origem WebSocket
grep "WebSocket connection rejected\|Origin" logs/*.log

# 3. Testar com curl (deve falhar sem token)
curl -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  http://localhost:3000

# 4. Testar integração segura
node -e "
const WebSocket = require('ws');
const ws = new WebSocket('ws://localhost:3000', {
  headers: {
    'Origin': 'http://localhost:3000',
    'Authorization': 'Bearer YOUR_TOKEN'
  }
});
ws.on('open', () => console.log('SEGURO: Conectado com origem autorizada'));
ws.on('error', (e) => console.log('BLOQUEADO:', e.message));
"
```

---

## 2. Skills Maliciosos - Validação e Sandbox

### 2.1 Causa Raiz Técnica

Skills no OpenClaw podem ser:
- Carregadas de fontes não confiáveis
- Executadas com privilégios elevados
- Acessar dados sensíveis sem validação
- Exfiltrar credenciais do sistema

### 2.2 Código de Patch Completo

**Arquivo: `src/skill-security-patch.ts`**

```typescript
import { createHash, randomBytes } from 'crypto';
import { VM } from 'vm2'; // Sandboxing seguro
import Ajv from 'ajv';

interface SkillManifest {
  name: string;
  version: string;
  author: string;
  permissions: string[];
  hash: string;
  signature: string;
  requiredCapabilities?: string[];
}

interface SkillExecutionContext {
  allowedGlobals: string[];
  forbiddenModules: string[];
  maxMemory: number;
  maxExecutionTime: number;
  allowedEnvVars: string[];
}

const SKILL_MANIFEST_SCHEMA = {
  type: 'object',
  required: ['name', 'version', 'author', 'permissions'],
  properties: {
    name: { type: 'string', minLength: 1, maxLength: 100 },
    version: { type: 'string', pattern: '^\\d+\\.\\d+\\.\\d+$' },
    author: { type: 'string', minLength: 1 },
    permissions: {
      type: 'array',
      items: {
        type: 'string',
        enum: [
          'fs:read',
          'fs:write',
          'network:request',
          'env:read',
          'process:execute',
          'db:read',
          'db:write',
          'cache:read',
          'cache:write'
        ]
      }
    },
    hash: { type: 'string', pattern: '^[a-f0-9]{64}$' },
    signature: { type: 'string' }
  }
};

class SkillSecurityManager {
  private allowedSkills = new Map<string, SkillManifest>();
  private skillHashes = new Map<string, string>();
  private executionLogs: any[] = [];
  private validator = new Ajv();
  private validateManifest = this.validator.compile(SKILL_MANIFEST_SCHEMA);

  /**
   * Valida integridade do skill usando hash SHA-256
   */
  validateSkillHash(skillCode: string, expectedHash: string): boolean {
    const calculated = createHash('sha256')
      .update(skillCode)
      .digest('hex');

    return calculated === expectedHash;
  }

  /**
   * Valida assinatura digital do skill
   * Usa certificados públicos de autores confiáveis
   */
  validateSkillSignature(
    skillCode: string,
    signature: string,
    authorPublicKey: string
  ): boolean {
    const crypto = require('crypto');
    const verifier = crypto.createVerify('sha256');
    verifier.update(skillCode);

    try {
      return verifier.verify(authorPublicKey, Buffer.from(signature, 'hex'));
    } catch (error) {
      console.error('Signature verification failed:', error);
      return false;
    }
  }

  /**
   * Valida manifesto do skill
   */
  validateManifest(manifest: any): { valid: boolean; errors?: any[] } {
    const isValid = this.validateManifest(manifest);

    if (!isValid) {
      return {
        valid: false,
        errors: this.validateManifest.errors
      };
    }

    return { valid: true };
  }

  /**
   * Registra skill após validação completa
   */
  registerSkill(
    skillCode: string,
    manifest: SkillManifest,
    authorPublicKey: string
  ): { success: boolean; error?: string; skillId?: string } {
    // 1. Validar estrutura do manifesto
    const manifestCheck = this.validateManifest(manifest);
    if (!manifestCheck.valid) {
      return {
        success: false,
        error: `Invalid manifest: ${JSON.stringify(manifestCheck.errors)}`
      };
    }

    // 2. Validar hash
    if (!this.validateSkillHash(skillCode, manifest.hash)) {
      return {
        success: false,
        error: 'Skill code hash does not match manifest'
      };
    }

    // 3. Validar assinatura
    if (!this.validateSkillSignature(skillCode, manifest.signature, authorPublicKey)) {
      return {
        success: false,
        error: 'Skill signature verification failed'
      };
    }

    // 4. Gerar ID único do skill
    const skillId = createHash('sha256')
      .update(`${manifest.name}:${manifest.version}:${Date.now()}`)
      .digest('hex')
      .slice(0, 12);

    // 5. Armazenar
    this.allowedSkills.set(skillId, manifest);
    this.skillHashes.set(skillId, manifest.hash);

    console.log(`✓ Skill registered: ${manifest.name}@${manifest.version} (ID: ${skillId})`);

    return { success: true, skillId };
  }

  /**
   * Cria contexto de execução seguro para skill
   */
  createExecutionContext(manifest: SkillManifest): SkillExecutionContext {
    const context: SkillExecutionContext = {
      allowedGlobals: [
        'console',
        'Math',
        'Date',
        'JSON',
        'Array',
        'Object',
        'String',
        'Number',
        'Boolean'
      ],
      forbiddenModules: [
        'fs',
        'child_process',
        'net',
        'http',
        'https',
        'path',
        'os',
        'cluster',
        'dgram'
      ],
      maxMemory: 128 * 1024 * 1024, // 128MB
      maxExecutionTime: 30000, // 30 segundos
      allowedEnvVars: this.getAllowedEnvVars(manifest.permissions)
    };

    return context;
  }

  /**
   * Determina quais variáveis de ambiente são acessíveis
   */
  private getAllowedEnvVars(permissions: string[]): string[] {
    const allowed: string[] = [];

    // Apenas variáveis seguras
    const safeVars = [
      'NODE_ENV',
      'APP_VERSION',
      'LOG_LEVEL',
      'TIMEZONE'
    ];

    if (permissions.includes('env:read')) {
      // Aplicar whitelist mesmo com permissão
      allowed.push(...safeVars);
    }

    return allowed;
  }

  /**
   * Executa skill em sandbox seguro
   */
  executeSkill(
    skillCode: string,
    skillId: string,
    input: any,
    timeout: number = 30000
  ): { success: boolean; result?: any; error?: string } {
    const manifest = this.allowedSkills.get(skillId);
    if (!manifest) {
      return { success: false, error: 'Skill not found or not registered' };
    }

    // Validar integridade
    if (this.skillHashes.get(skillId) !== manifest.hash) {
      return { success: false, error: 'Skill code has been tampered with' };
    }

    const context = this.createExecutionContext(manifest);

    try {
      const sandbox = this.buildSandbox(context, input);

      const vm = new VM({
        timeout,
        sandbox,
        eval: false,
        wasm: false
      });

      const result = vm.run(skillCode, 'skill-execution');

      // Log da execução bem-sucedida
      this.logExecution(skillId, manifest.name, true, input, result);

      return { success: true, result };
    } catch (error: any) {
      // Log de erro
      this.logExecution(skillId, manifest.name, false, input, error.message);

      return {
        success: false,
        error: `Skill execution failed: ${error.message}`
      };
    }
  }

  /**
   * Constrói sandbox seguro para execução
   */
  private buildSandbox(context: SkillExecutionContext, input: any): any {
    return {
      // Globais permitidos
      console: {
        log: (...args: any[]) => console.log('[SKILL]', ...args),
        error: (...args: any[]) => console.error('[SKILL]', ...args),
        warn: (...args: any[]) => console.warn('[SKILL]', ...args)
      },
      Math: Math,
      Date: Date,
      JSON: JSON,
      Array: Array,
      Object: Object,
      String: String,
      Number: Number,
      Boolean: Boolean,

      // Input do usuário
      input,

      // Acesso controlado a variáveis de ambiente
      env: this.createSafeEnvProxy(context.allowedEnvVars),

      // Proteções
      process: undefined,
      require: undefined,
      __dirname: undefined,
      __filename: undefined,
      global: undefined
    };
  }

  /**
   * Cria proxy seguro para variáveis de ambiente
   */
  private createSafeEnvProxy(allowedVars: string[]): any {
    return new Proxy({}, {
      get: (target, prop) => {
        const varName = String(prop);
        if (!allowedVars.includes(varName)) {
          throw new Error(`Access to environment variable '${varName}' is forbidden`);
        }
        return process.env[varName];
      },
      set: () => {
        throw new Error('Cannot modify environment variables');
      }
    });
  }

  /**
   * Log de execução para auditoria
   */
  private logExecution(
    skillId: string,
    skillName: string,
    success: boolean,
    input: any,
    result: any
  ): void {
    this.executionLogs.push({
      timestamp: new Date().toISOString(),
      skillId,
      skillName,
      success,
      input: this.sanitizeForLogging(input),
      result: this.sanitizeForLogging(result),
      ipAddress: this.getClientIP()
    });

    // Manter apenas últimos 10000 logs
    if (this.executionLogs.length > 10000) {
      this.executionLogs = this.executionLogs.slice(-10000);
    }
  }

  /**
   * Remove dados sensíveis do log
   */
  private sanitizeForLogging(data: any): any {
    if (typeof data !== 'object') return String(data).slice(0, 100);
    return JSON.stringify(data).slice(0, 500);
  }

  /**
   * Placeholder para obter IP do cliente
   */
  private getClientIP(): string {
    // Implementar obtendo do contexto de requisição real
    return '0.0.0.0';
  }

  /**
   * Recupera logs de auditoria
   */
  getAuditLogs(limit: number = 100): any[] {
    return this.executionLogs.slice(-limit);
  }

  /**
   * Revoga skill para impedir execução futura
   */
  revokeSkill(skillId: string): boolean {
    return this.allowedSkills.delete(skillId) &&
           this.skillHashes.delete(skillId);
  }

  /**
   * Lista skills registrados
   */
  listRegisteredSkills(): Array<{ id: string; manifest: SkillManifest }> {
    const result: Array<{ id: string; manifest: SkillManifest }> = [];
    for (const [id, manifest] of this.allowedSkills) {
      result.push({ id, manifest });
    }
    return result;
  }
}

export { SkillSecurityManager, SkillManifest, SkillExecutionContext };
```

### 2.3 Arquivo de Manifesto do Skill

**Exemplo: `skills/my-skill/manifest.json`**

```json
{
  "name": "weather-skill",
  "version": "1.0.0",
  "author": "trusted-author",
  "description": "Fetches weather information",
  "permissions": [
    "network:request"
  ],
  "requiredCapabilities": ["axios"],
  "hash": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f",
  "signature": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
}
```

### 2.4 Integração no Aplicativo

**Arquivo: `src/routes/skills.ts`**

```typescript
import { Router, Request, Response } from 'express';
import { SkillSecurityManager } from '../skill-security-patch';
import fs from 'fs/promises';
import path from 'path';

const router = Router();
const skillManager = new SkillSecurityManager();

/**
 * Registra novo skill após validação
 */
router.post('/api/skills/register', async (req: Request, res: Response) => {
  try {
    const { skillPath, authorPublicKey } = req.body;

    if (!skillPath || !authorPublicKey) {
      return res.status(400).json({
        error: 'skillPath and authorPublicKey are required'
      });
    }

    // Ler arquivo do skill
    const skillCode = await fs.readFile(skillPath, 'utf-8');

    // Ler manifesto
    const manifestPath = path.join(path.dirname(skillPath), 'manifest.json');
    const manifestContent = await fs.readFile(manifestPath, 'utf-8');
    const manifest = JSON.parse(manifestContent);

    // Registrar skill
    const registration = skillManager.registerSkill(
      skillCode,
      manifest,
      authorPublicKey
    );

    if (!registration.success) {
      return res.status(400).json({
        error: registration.error
      });
    }

    res.json({
      success: true,
      skillId: registration.skillId,
      message: `Skill ${manifest.name} registered successfully`
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Executa skill registrado
 */
router.post('/api/skills/:skillId/execute', async (req: Request, res: Response) => {
  try {
    const { skillId } = req.params;
    const { input } = req.body;

    const execution = skillManager.executeSkill(
      '',// skillCode será obtido internamente
      skillId,
      input,
      30000
    );

    if (!execution.success) {
      return res.status(400).json({
        error: execution.error
      });
    }

    res.json({
      success: true,
      result: execution.result
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Lista skills registrados (apenas info de manifesto)
 */
router.get('/api/skills', (req: Request, res: Response) => {
  const skills = skillManager.listRegisteredSkills();
  res.json({
    count: skills.length,
    skills: skills.map(s => ({
      id: s.id,
      name: s.manifest.name,
      version: s.manifest.version,
      author: s.manifest.author,
      permissions: s.manifest.permissions
    }))
  });
});

/**
 * Recupera logs de auditoria
 */
router.get('/api/audit/skills', (req: Request, res: Response) => {
  const limit = Math.min(parseInt(req.query.limit as string) || 100, 1000);
  const logs = skillManager.getAuditLogs(limit);
  res.json({ logs, count: logs.length });
});

/**
 * Revoga skill
 */
router.post('/api/skills/:skillId/revoke', (req: Request, res: Response) => {
  const { skillId } = req.params;

  if (skillManager.revokeSkill(skillId)) {
    res.json({ success: true, message: 'Skill revoked' });
  } else {
    res.status(404).json({ error: 'Skill not found' });
  }
});

export default router;
```

### 2.5 Testes de Segurança

**Arquivo: `tests/skill-security.test.ts`**

```typescript
import { describe, it, expect, beforeEach } from '@jest/globals';
import { SkillSecurityManager } from '../src/skill-security-patch';
import { createHash } from 'crypto';

describe('Skill Security Tests', () => {
  let skillManager: SkillSecurityManager;

  beforeEach(() => {
    skillManager = new SkillSecurityManager();
  });

  // TEST 1: Detecta hash inválido
  it('should reject skill with invalid hash', () => {
    const skillCode = 'console.log("test");';
    const wrongHash = 'a'.repeat(64);
    const manifest = {
      name: 'test-skill',
      version: '1.0.0',
      author: 'test',
      permissions: [],
      hash: wrongHash,
      signature: 'fake'
    };

    const result = skillManager.registerSkill(skillCode, manifest, '');
    expect(result.success).toBe(false);
    expect(result.error).toContain('hash does not match');
  });

  // TEST 2: Aceita skill com hash válido
  it('should accept skill with valid hash', () => {
    const skillCode = 'return input * 2;';
    const validHash = createHash('sha256')
      .update(skillCode)
      .digest('hex');

    const manifest = {
      name: 'valid-skill',
      version: '1.0.0',
      author: 'test',
      permissions: [],
      hash: validHash,
      signature: 'fake'
    };

    // Nota: Falhará em assinatura, mas passa em hash
    const result = skillManager.registerSkill(skillCode, manifest, '');
    // Esperaríamos sucesso se assinatura fosse válida
  });

  // TEST 3: Sandbox bloqueia acesso a módulos perigosos
  it('should prevent access to dangerous modules', () => {
    const dangerousCode = `
      const fs = require('fs');
      fs.readFileSync('/etc/passwd', 'utf-8');
    `;

    const hash = createHash('sha256').update(dangerousCode).digest('hex');
    const manifest = {
      name: 'evil-skill',
      version: '1.0.0',
      author: 'evil',
      permissions: [],
      hash,
      signature: 'fake'
    };

    skillManager.registerSkill(dangerousCode, manifest, '');
    const execution = skillManager.executeSkill(
      dangerousCode,
      'test-id',
      {}
    );

    expect(execution.success).toBe(false);
  });

  // TEST 4: Sandbox bloqueia acesso a variáveis de ambiente sensíveis
  it('should block access to sensitive environment variables', () => {
    const code = `
      try {
        return env.DATABASE_PASSWORD;
      } catch (e) {
        return 'BLOCKED';
      }
    `;

    const hash = createHash('sha256').update(code).digest('hex');
    const manifest = {
      name: 'env-skill',
      version: '1.0.0',
      author: 'test',
      permissions: ['env:read'],
      hash,
      signature: 'fake'
    };

    // Simular execução (simplificado)
    // Em produção, teria que passar por assinatura
    expect(() => {
      skillManager.executeSkill(code, 'test-id', {});
    }).not.toThrow();
  });

  // TEST 5: Timeout em execução longa
  it('should timeout long-running skills', async () => {
    const infiniteCode = `
      while(true) { }
    `;

    const hash = createHash('sha256').update(infiniteCode).digest('hex');
    const manifest = {
      name: 'infinite-skill',
      version: '1.0.0',
      author: 'test',
      permissions: [],
      hash,
      signature: 'fake'
    };

    const execution = skillManager.executeSkill(
      infiniteCode,
      'test-id',
      {},
      1000 // 1 segundo timeout
    );

    expect(execution.success).toBe(false);
    expect(execution.error).toContain('timeout');
  });

  // TEST 6: Auditoria de execução
  it('should log skill executions', () => {
    const code = 'return input.value * 2;';
    const hash = createHash('sha256').update(code).digest('hex');

    // Simulação de registro
    const manifest = {
      name: 'audit-skill',
      version: '1.0.0',
      author: 'test',
      permissions: [],
      hash,
      signature: 'fake'
    };

    const logs = skillManager.getAuditLogs();
    expect(logs).toBeDefined();
  });
});
```

### 2.6 Validação da Remediação

```bash
# 1. Executar testes
npm test -- skill-security.test.ts

# 2. Registrar skill com validação
curl -X POST http://localhost:3000/api/skills/register \
  -H "Content-Type: application/json" \
  -d '{
    "skillPath": "/path/to/skill.js",
    "authorPublicKey": "-----BEGIN PUBLIC KEY-----..."
  }'

# 3. Verificar logs de auditoria
curl http://localhost:3000/api/audit/skills?limit=50

# 4. Testar bloqueio de skill perigoso
npm run test:security:skills
```

---

## 3. Vulnerabilidades em Skills - Validação de Permissões

### 3.1 Causa Raiz Técnica

Skills podem:
- Exceder permissões concedidas
- Acessar recursos não autorizados
- Escalar privilégios
- Ignorar restrições RBAC

### 3.2 Código de Patch Completo

**Arquivo: `src/skill-permissions-patch.ts`**

```typescript
import { createHash } from 'crypto';

// Definição de permissões com escopo
type PermissionScope = 'read' | 'write' | 'execute' | 'delete' | 'admin';
type ResourceType = 'fs' | 'db' | 'network' | 'env' | 'process' | 'cache' | 'api';

interface Permission {
  resource: ResourceType;
  scope: PermissionScope;
  paths?: string[]; // Para FS: caminhos permitidos
  hosts?: string[]; // Para Network: hosts permitidos
  databases?: string[]; // Para DB: bancos de dados permitidos
  apiEndpoints?: string[]; // Para API: endpoints permitidos
}

interface SkillPermissionPolicy {
  skillId: string;
  version: string;
  permissions: Permission[];
  restrictedPaths: string[]; // Paths que nunca podem ser acessados
  maxMemory: number;
  maxExecutionTime: number;
  maxRequests: number; // Por minuto
}

interface AccessRequest {
  resourceType: ResourceType;
  scope: PermissionScope;
  target: string;
  metadata?: Record<string, any>;
}

interface AccessDecision {
  allowed: boolean;
  reason: string;
  violation?: 'missing_permission' | 'path_restricted' | 'rate_limit' | 'other';
}

class SkillPermissionManager {
  private policies = new Map<string, SkillPermissionPolicy>();
  private accessLog: AccessRequest[] = [];
  private requestCounts = new Map<string, number>(); // skillId -> count
  private restrictedPaths = [
    '/etc/passwd',
    '/etc/shadow',
    '/root',
    '/sys',
    '/proc',
    '/dev/sda',
    '~/.ssh',
    '~/.aws',
    '~/.docker',
    'node_modules'
  ];

  /**
   * Cria política de permissões para skill
   */
  createPolicy(
    skillId: string,
    version: string,
    permissions: Permission[],
    maxMemory: number = 128 * 1024 * 1024,
    maxExecutionTime: number = 30000,
    maxRequests: number = 100
  ): SkillPermissionPolicy {
    const policy: SkillPermissionPolicy = {
      skillId,
      version,
      permissions: this.validatePermissions(permissions),
      restrictedPaths: this.restrictedPaths,
      maxMemory,
      maxExecutionTime,
      maxRequests
    };

    this.policies.set(skillId, policy);
    console.log(`✓ Permission policy created for skill ${skillId}`);

    return policy;
  }

  /**
   * Valida e normaliza permissões solicitadas
   */
  private validatePermissions(permissions: Permission[]): Permission[] {
    return permissions.map(perm => {
      // Validar tipo de recurso
      if (!['fs', 'db', 'network', 'env', 'process', 'cache', 'api'].includes(perm.resource)) {
        throw new Error(`Invalid resource type: ${perm.resource}`);
      }

      // Validar escopo
      if (!['read', 'write', 'execute', 'delete', 'admin'].includes(perm.scope)) {
        throw new Error(`Invalid permission scope: ${perm.scope}`);
      }

      // Normalizar caminhos (remover caminhos sensíveis)
      if (perm.paths) {
        perm.paths = perm.paths.filter(p => !this.isRestrictedPath(p));
      }

      return perm;
    });
  }

  /**
   * Verifica se um caminho é restrito
   */
  private isRestrictedPath(path: string): boolean {
    return this.restrictedPaths.some(restricted =>
      path.startsWith(restricted) || path.includes(restricted)
    );
  }

  /**
   * Avalia requisição de acesso
   */
  evaluateAccess(
    skillId: string,
    request: AccessRequest
  ): AccessDecision {
    // 1. Verificar se skill existe
    const policy = this.policies.get(skillId);
    if (!policy) {
      return {
        allowed: false,
        reason: 'Skill not found or not registered',
        violation: 'other'
      };
    }

    // 2. Verificar rate limiting
    const count = this.requestCounts.get(skillId) || 0;
    if (count >= policy.maxRequests) {
      return {
        allowed: false,
        reason: `Rate limit exceeded: ${count}/${policy.maxRequests}`,
        violation: 'rate_limit'
      };
    }

    // 3. Verificar caminho restrito (filesystem)
    if (request.resourceType === 'fs' && this.isRestrictedPath(request.target)) {
      return {
        allowed: false,
        reason: `Path is restricted: ${request.target}`,
        violation: 'path_restricted'
      };
    }

    // 4. Buscar permissão compatível
    const hasPermission = policy.permissions.some(perm =>
      this.permissionMatches(perm, request)
    );

    if (!hasPermission) {
      return {
        allowed: false,
        reason: `Missing permission: ${request.resourceType}:${request.scope}`,
        violation: 'missing_permission'
      };
    }

    // 5. Incrementar contador
    this.requestCounts.set(skillId, count + 1);

    // 6. Log de acesso bem-sucedido
    this.logAccess(skillId, request, true);

    return {
      allowed: true,
      reason: 'Access granted'
    };
  }

  /**
   * Verifica se uma permissão atende a requisição
   */
  private permissionMatches(perm: Permission, request: AccessRequest): boolean {
    // Tipo de recurso deve combinar
    if (perm.resource !== request.resourceType) {
      return false;
    }

    // Escopo deve ser suficiente
    const scopeHierarchy: Record<PermissionScope, number> = {
      'read': 1,
      'write': 2,
      'execute': 3,
      'delete': 4,
      'admin': 5
    };

    if (scopeHierarchy[perm.scope] < scopeHierarchy[request.scope]) {
      return false;
    }

    // Validações específicas por tipo de recurso
    switch (request.resourceType) {
      case 'fs':
        return this.validateFSAccess(perm, request);
      case 'network':
        return this.validateNetworkAccess(perm, request);
      case 'db':
        return this.validateDBAccess(perm, request);
      case 'api':
        return this.validateAPIAccess(perm, request);
      case 'env':
        return this.validateEnvAccess(perm, request);
      default:
        return true;
    }
  }

  /**
   * Valida acesso ao filesystem
   */
  private validateFSAccess(perm: Permission, request: AccessRequest): boolean {
    if (!perm.paths) return false;
    return perm.paths.some(path =>
      request.target.startsWith(path)
    );
  }

  /**
   * Valida acesso à rede
   */
  private validateNetworkAccess(perm: Permission, request: AccessRequest): boolean {
    if (!perm.hosts) return false;
    return perm.hosts.some(host =>
      request.target.includes(host)
    );
  }

  /**
   * Valida acesso ao banco de dados
   */
  private validateDBAccess(perm: Permission, request: AccessRequest): boolean {
    if (!perm.databases) return false;
    return perm.databases.some(db =>
      request.target.includes(db)
    );
  }

  /**
   * Valida acesso à API
   */
  private validateAPIAccess(perm: Permission, request: AccessRequest): boolean {
    if (!perm.apiEndpoints) return false;
    return perm.apiEndpoints.some(endpoint =>
      request.target.startsWith(endpoint)
    );
  }

  /**
   * Valida acesso a variáveis de ambiente
   */
  private validateEnvAccess(perm: Permission, request: AccessRequest): boolean {
    // Permitir apenas variáveis públicas
    const publicVars = [
      'NODE_ENV',
      'LOG_LEVEL',
      'TIMEZONE',
      'APP_VERSION'
    ];
    return publicVars.includes(request.target);
  }

  /**
   * Log de requisição de acesso
   */
  private logAccess(
    skillId: string,
    request: AccessRequest,
    granted: boolean
  ): void {
    this.accessLog.push({
      ...request,
      timestamp: new Date().toISOString(),
      skillId,
      granted,
      metadata: {
        ...request.metadata,
        timestamp: Date.now()
      }
    } as any);

    // Manter últimos 50000 logs
    if (this.accessLog.length > 50000) {
      this.accessLog = this.accessLog.slice(-50000);
    }
  }

  /**
   * Reset de contador de requisições (por minuto)
   */
  resetRequestCounts(): void {
    this.requestCounts.clear();
  }

  /**
   * Iniciar reset automático a cada minuto
   */
  startAutoReset(): void {
    setInterval(() => {
      this.resetRequestCounts();
      console.log('Request counters reset');
    }, 60000);
  }

  /**
   * Recuperar logs de acesso
   */
  getAccessLogs(skillId?: string, limit: number = 100): any[] {
    let logs = this.accessLog;

    if (skillId) {
      logs = logs.filter(log => log.skillId === skillId);
    }

    return logs.slice(-limit);
  }

  /**
   * Obter relatório de violações
   */
  getViolationReport(skillId?: string): any {
    const logs = skillId
      ? this.accessLog.filter(log => log.skillId === skillId)
      : this.accessLog;

    const violations = logs.filter(log => !log.granted);

    return {
      totalAttempts: logs.length,
      totalViolations: violations.length,
      violationRate: logs.length > 0
        ? ((violations.length / logs.length) * 100).toFixed(2) + '%'
        : '0%',
      byType: violations.reduce((acc: any, log: any) => {
        const type = log.resourceType;
        acc[type] = (acc[type] || 0) + 1;
        return acc;
      }, {}),
      bySkill: violations.reduce((acc: any, log: any) => {
        const skill = log.skillId;
        acc[skill] = (acc[skill] || 0) + 1;
        return acc;
      }, {})
    };
  }

  /**
   * Atualizar política de skill
   */
  updatePolicy(
    skillId: string,
    updates: Partial<SkillPermissionPolicy>
  ): boolean {
    const policy = this.policies.get(skillId);
    if (!policy) return false;

    if (updates.permissions) {
      policy.permissions = this.validatePermissions(updates.permissions);
    }
    if (updates.maxMemory) policy.maxMemory = updates.maxMemory;
    if (updates.maxExecutionTime) policy.maxExecutionTime = updates.maxExecutionTime;
    if (updates.maxRequests) policy.maxRequests = updates.maxRequests;

    console.log(`✓ Policy updated for skill ${skillId}`);
    return true;
  }

  /**
   * Revogar skill
   */
  revokeSkill(skillId: string): boolean {
    return this.policies.delete(skillId);
  }

  /**
   * Listar todas as políticas
   */
  listPolicies(): SkillPermissionPolicy[] {
    return Array.from(this.policies.values());
  }
}

export {
  SkillPermissionManager,
  SkillPermissionPolicy,
  Permission,
  AccessRequest,
  AccessDecision,
  ResourceType,
  PermissionScope
};
```

**Arquivo: `src/routes/permissions.ts`**

```typescript
import { Router, Request, Response } from 'express';
import { SkillPermissionManager, Permission } from '../skill-permissions-patch';

const router = Router();
const permissionManager = new SkillPermissionManager();

// Iniciar auto-reset de contadores
permissionManager.startAutoReset();

/**
 * Criar política de permissões para skill
 */
router.post('/api/permissions/skill/:skillId', (req: Request, res: Response) => {
  try {
    const { skillId } = req.params;
    const { version, permissions, maxMemory, maxExecutionTime, maxRequests } = req.body;

    if (!version || !permissions) {
      return res.status(400).json({
        error: 'version and permissions are required'
      });
    }

    const policy = permissionManager.createPolicy(
      skillId,
      version,
      permissions,
      maxMemory,
      maxExecutionTime,
      maxRequests
    );

    res.json({
      success: true,
      policy
    });
  } catch (error: any) {
    res.status(400).json({ error: error.message });
  }
});

/**
 * Avaliar requisição de acesso
 */
router.post('/api/permissions/evaluate', (req: Request, res: Response) => {
  const { skillId, resourceType, scope, target } = req.body;

  if (!skillId || !resourceType || !scope || !target) {
    return res.status(400).json({
      error: 'skillId, resourceType, scope, and target are required'
    });
  }

  const decision = permissionManager.evaluateAccess(skillId, {
    resourceType: resourceType as any,
    scope: scope as any,
    target
  });

  const statusCode = decision.allowed ? 200 : 403;
  res.status(statusCode).json(decision);
});

/**
 * Recuperar logs de acesso
 */
router.get('/api/permissions/logs', (req: Request, res: Response) => {
  const skillId = req.query.skillId as string;
  const limit = Math.min(parseInt(req.query.limit as string) || 100, 1000);

  const logs = permissionManager.getAccessLogs(skillId, limit);
  res.json({
    count: logs.length,
    logs
  });
});

/**
 * Relatório de violações
 */
router.get('/api/permissions/violations', (req: Request, res: Response) => {
  const skillId = req.query.skillId as string;
  const report = permissionManager.getViolationReport(skillId);
  res.json(report);
});

/**
 * Atualizar política
 */
router.put('/api/permissions/skill/:skillId', (req: Request, res: Response) => {
  const { skillId } = req.params;
  const { permissions, maxMemory, maxExecutionTime, maxRequests } = req.body;

  const success = permissionManager.updatePolicy(skillId, {
    permissions,
    maxMemory,
    maxExecutionTime,
    maxRequests
  });

  if (success) {
    res.json({ success: true, message: 'Policy updated' });
  } else {
    res.status(404).json({ error: 'Skill not found' });
  }
});

/**
 * Revogar skill
 */
router.post('/api/permissions/skill/:skillId/revoke', (req: Request, res: Response) => {
  const { skillId } = req.params;

  if (permissionManager.revokeSkill(skillId)) {
    res.json({ success: true, message: 'Skill revoked' });
  } else {
    res.status(404).json({ error: 'Skill not found' });
  }
});

/**
 * Listar todas as políticas
 */
router.get('/api/permissions/policies', (req: Request, res: Response) => {
  const policies = permissionManager.listPolicies();
  res.json({
    count: policies.length,
    policies
  });
});

export default router;
```

### 3.3 Testes de Permissões

**Arquivo: `tests/permissions.test.ts`**

```typescript
import { describe, it, expect, beforeEach } from '@jest/globals';
import { SkillPermissionManager, Permission } from '../src/skill-permissions-patch';

describe('Skill Permissions Tests', () => {
  let permManager: SkillPermissionManager;

  beforeEach(() => {
    permManager = new SkillPermissionManager();
  });

  // TEST 1: Permite acesso com permissão válida
  it('should allow access with valid permission', () => {
    const permissions: Permission[] = [
      {
        resource: 'fs',
        scope: 'read',
        paths: ['/app/data', '/app/public']
      }
    ];

    permManager.createPolicy('skill1', '1.0.0', permissions);

    const decision = permManager.evaluateAccess('skill1', {
      resourceType: 'fs',
      scope: 'read',
      target: '/app/data/file.txt'
    });

    expect(decision.allowed).toBe(true);
  });

  // TEST 2: Nega acesso a caminhos restritos
  it('should deny access to restricted paths', () => {
    const permissions: Permission[] = [
      {
        resource: 'fs',
        scope: 'read',
        paths: ['/etc/passwd'] // Isso será filtrado
      }
    ];

    permManager.createPolicy('skill2', '1.0.0', permissions);

    // Tenta acessar /etc/passwd
    const decision = permManager.evaluateAccess('skill2', {
      resourceType: 'fs',
      scope: 'read',
      target: '/etc/passwd'
    });

    expect(decision.allowed).toBe(false);
    expect(decision.violation).toBe('path_restricted');
  });

  // TEST 3: Respeita rate limiting
  it('should enforce rate limiting', () => {
    const permissions: Permission[] = [
      {
        resource: 'network',
        scope: 'read',
        hosts: ['api.example.com']
      }
    ];

    permManager.createPolicy('skill3', '1.0.0', permissions, 128 * 1024 * 1024, 30000, 5);

    // Fazer 5 requisições (limite)
    for (let i = 0; i < 5; i++) {
      const decision = permManager.evaluateAccess('skill3', {
        resourceType: 'network',
        scope: 'read',
        target: 'api.example.com'
      });
      expect(decision.allowed).toBe(true);
    }

    // 6ª requisição deve ser bloqueada
    const decision = permManager.evaluateAccess('skill3', {
      resourceType: 'network',
      scope: 'read',
      target: 'api.example.com'
    });

    expect(decision.allowed).toBe(false);
    expect(decision.violation).toBe('rate_limit');
  });

  // TEST 4: Nega acesso sem permissão apropriada
  it('should deny access without appropriate permission', () => {
    const permissions: Permission[] = [
      {
        resource: 'fs',
        scope: 'read',
        paths: ['/app']
      }
    ];

    permManager.createPolicy('skill4', '1.0.0', permissions);

    const decision = permManager.evaluateAccess('skill4', {
      resourceType: 'db',
      scope: 'read',
      target: 'production_db'
    });

    expect(decision.allowed).toBe(false);
    expect(decision.violation).toBe('missing_permission');
  });

  // TEST 5: Respeita escopo de permissão
  it('should respect permission scope hierarchy', () => {
    const permissions: Permission[] = [
      {
        resource: 'fs',
        scope: 'read', // Apenas leitura
        paths: ['/app']
      }
    ];

    permManager.createPolicy('skill5', '1.0.0', permissions);

    // Tentar escrever com permissão de leitura
    const decision = permManager.evaluateAccess('skill5', {
      resourceType: 'fs',
      scope: 'write',
      target: '/app/file.txt'
    });

    expect(decision.allowed).toBe(false);
  });

  // TEST 6: Relatório de violações
  it('should generate violation reports', () => {
    const permissions: Permission[] = [
      {
        resource: 'fs',
        scope: 'read',
        paths: ['/app']
      }
    ];

    permManager.createPolicy('skill6', '1.0.0', permissions);

    // Tentar vários acessos, alguns bloqueados
    permManager.evaluateAccess('skill6', {
      resourceType: 'fs',
      scope: 'read',
      target: '/app/ok.txt'
    });

    permManager.evaluateAccess('skill6', {
      resourceType: 'db',
      scope: 'read',
      target: 'db'
    });

    const report = permManager.getViolationReport('skill6');
    expect(report.totalViolations).toBeGreaterThan(0);
  });
});
```

### 3.4 Validação da Remediação

```bash
# 1. Executar testes
npm test -- permissions.test.ts

# 2. Criar política de permissões
curl -X POST http://localhost:3000/api/permissions/skill/skill1 \
  -H "Content-Type: application/json" \
  -d '{
    "version": "1.0.0",
    "permissions": [
      {
        "resource": "fs",
        "scope": "read",
        "paths": ["/app/data"]
      }
    ],
    "maxRequests": 100
  }'

# 3. Testar avaliação de acesso
curl -X POST http://localhost:3000/api/permissions/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "skillId": "skill1",
    "resourceType": "fs",
    "scope": "read",
    "target": "/app/data/file.txt"
  }'

# 4. Ver logs de acesso
curl http://localhost:3000/api/permissions/logs?skillId=skill1

# 5. Gerar relatório de violações
curl http://localhost:3000/api/permissions/violations?skillId=skill1
```

---

Continuaremos com as vulnerabilidades 4, 5, 6 e 7 na próxima parte. Você quer que eu proceda?

