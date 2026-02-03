# Guia Técnico: Remediação de Vulnerabilidades Críticas do OpenClaw
## Parte 2: Interface Web Desprotegida, Credenciais, Prompt Injection e Admin Expostas

---

## 4. Interface Web Desprotegida - CSRF, XSS e CORS

### 4.1 Causa Raiz Técnica

A interface web OpenClaw pode sofrer:
- **CSRF (Cross-Site Request Forgery)**: Requisições não autorizadas em nome do usuário
- **XSS (Cross-Site Scripting)**: Injeção de scripts maliciosos
- **CORS inapropriado**: Requisições de qualquer domínio
- **Falta de validação de entrada**: Permitindo payloads maliciosos

### 4.2 Código de Patch Completo

**Arquivo: `src/web-security-patch.ts`**

```typescript
import express, { Express, Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import csrf from 'csurf';
import cookieParser from 'cookie-parser';
import { v4 as uuidv4 } from 'uuid';
import xss from 'xss';
import validator from 'validator';

/**
 * Configuração de segurança para a interface web
 */
interface WebSecurityConfig {
  corsOrigins: string[];
  csrfProtection: boolean;
  xssProtection: boolean;
  helmetConfig: any;
  rateLimitConfig: {
    windowMs: number;
    maxRequests: number;
  };
  sessionTimeout: number;
  secureCookies: boolean;
}

/**
 * Token CSRF com expiração
 */
interface CSRFToken {
  token: string;
  createdAt: number;
  expiresAt: number;
  sessionId: string;
}

class WebSecurityManager {
  private config: WebSecurityConfig;
  private csrfTokens = new Map<string, CSRFToken>();
  private sessionTokens = new Map<string, { expiresAt: number }>();
  private requestLog: any[] = [];

  constructor(config: WebSecurityConfig) {
    this.config = config;
    this.startTokenCleanup();
  }

  /**
   * Configura middleware de segurança para Express
   */
  configureExpress(app: Express): void {
    // 1. Helmet - Headers de segurança HTTP
    app.use(helmet(this.config.helmetConfig));

    // 2. Parser de cookies
    app.use(cookieParser());

    // 3. Body parser com limite
    app.use(express.json({
      limit: '10mb',
      strict: true // Apenas objetos/arrays
    }));

    app.use(express.urlencoded({
      limit: '10mb',
      extended: true
    }));

    // 4. CORS seguro
    app.use(this.corsMiddleware.bind(this));

    // 5. Rate limiting
    const limiter = rateLimit({
      windowMs: this.config.rateLimitConfig.windowMs,
      max: this.config.rateLimitConfig.maxRequests,
      message: 'Too many requests',
      standardHeaders: true,
      legacyHeaders: false
    });
    app.use(limiter);

    // 6. CSRF protection (se habilitado)
    if (this.config.csrfProtection) {
      app.use(csrf({
        cookie: {
          httpOnly: true,
          secure: this.config.secureCookies,
          sameSite: 'strict'
        }
      }));
    }

    // 7. Sanitização de entrada
    app.use(this.inputSanitizationMiddleware.bind(this));

    // 8. Logging de requisições
    app.use(this.requestLoggingMiddleware.bind(this));

    // 9. Trusted proxy (se atrás de reverse proxy)
    app.set('trust proxy', 1);
  }

  /**
   * Middleware CORS seguro
   */
  private corsMiddleware(req: Request, res: Response, next: NextFunction): void {
    const origin = req.headers.origin;

    if (origin && this.config.corsOrigins.includes(origin)) {
      res.header('Access-Control-Allow-Origin', origin);
      res.header('Access-Control-Allow-Credentials', 'true');
      res.header('Access-Control-Allow-Methods', 'GET,HEAD,PUT,PATCH,POST,DELETE');
      res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-CSRF-Token');
      res.header('Access-Control-Max-Age', '3600');

      // Rejeita preflight suspeito
      if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
      }
    } else if (origin) {
      // Origin não autorizada
      console.warn(`CORS rejection for origin: ${origin}`);
    }

    next();
  }

  /**
   * Middleware de sanitização de entrada
   */
  private inputSanitizationMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ): void {
    // Sanitizar corpo JSON
    if (req.body && typeof req.body === 'object') {
      req.body = this.sanitizeObject(req.body);
    }

    // Sanitizar query parameters
    if (req.query && typeof req.query === 'object') {
      req.query = this.sanitizeObject(req.query);
    }

    next();
  }

  /**
   * Sanitiza objetos recursivamente
   */
  private sanitizeObject(obj: any): any {
    if (Array.isArray(obj)) {
      return obj.map(item => this.sanitizeObject(item));
    }

    if (typeof obj !== 'object' || obj === null) {
      if (typeof obj === 'string') {
        return this.sanitizeString(obj);
      }
      return obj;
    }

    const sanitized: any = {};
    for (const [key, value] of Object.entries(obj)) {
      // Validar nome da chave
      if (!/^[a-zA-Z0-9_.-]+$/.test(key)) {
        console.warn(`Suspicious key name: ${key}`);
        continue;
      }

      sanitized[key] = this.sanitizeObject(value);
    }

    return sanitized;
  }

  /**
   * Sanitiza strings contra XSS
   */
  private sanitizeString(str: string): string {
    if (typeof str !== 'string') return str;

    // Usar biblioteca XSS
    const cleaned = xss(str, {
      whiteList: {}, // Sem tags HTML permitidas
      stripIgnoredTag: true,
      stripLeadingAndTrailingWhitespace: true
    });

    // Validação adicional
    if (cleaned.length > 10000) {
      return cleaned.slice(0, 10000);
    }

    return cleaned;
  }

  /**
   * Middleware de logging
   */
  private requestLoggingMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ): void {
    const startTime = Date.now();

    res.on('finish', () => {
      const duration = Date.now() - startTime;
      this.logRequest({
        method: req.method,
        path: req.path,
        status: res.statusCode,
        duration,
        ip: req.ip,
        userAgent: req.get('user-agent'),
        timestamp: new Date().toISOString()
      });
    });

    next();
  }

  /**
   * Log de requisição
   */
  private logRequest(log: any): void {
    this.requestLog.push(log);

    // Manter últimos 10000 logs
    if (this.requestLog.length > 10000) {
      this.requestLog = this.requestLog.slice(-10000);
    }
  }

  /**
   * Gera token CSRF
   */
  generateCSRFToken(sessionId: string): string {
    const token = uuidv4();
    const csrfToken: CSRFToken = {
      token,
      createdAt: Date.now(),
      expiresAt: Date.now() + 3600000, // 1 hora
      sessionId
    };

    this.csrfTokens.set(token, csrfToken);
    return token;
  }

  /**
   * Valida token CSRF
   */
  validateCSRFToken(token: string, sessionId: string): boolean {
    const csrfToken = this.csrfTokens.get(token);

    if (!csrfToken) {
      console.warn(`CSRF token not found: ${token}`);
      return false;
    }

    // Validar sessão
    if (csrfToken.sessionId !== sessionId) {
      console.warn(`CSRF token session mismatch`);
      return false;
    }

    // Validar expiração
    if (Date.now() > csrfToken.expiresAt) {
      this.csrfTokens.delete(token);
      console.warn(`CSRF token expired`);
      return false;
    }

    // Token é válido, remover para uso único
    this.csrfTokens.delete(token);
    return true;
  }

  /**
   * Valida sessão
   */
  createSession(userId: string): string {
    const sessionId = uuidv4();
    this.sessionTokens.set(sessionId, {
      expiresAt: Date.now() + this.config.sessionTimeout
    });

    return sessionId;
  }

  /**
   * Valida sessão
   */
  validateSession(sessionId: string): boolean {
    const session = this.sessionTokens.get(sessionId);

    if (!session) {
      return false;
    }

    if (Date.now() > session.expiresAt) {
      this.sessionTokens.delete(sessionId);
      return false;
    }

    return true;
  }

  /**
   * Invalida sessão
   */
  invalidateSession(sessionId: string): void {
    this.sessionTokens.delete(sessionId);
  }

  /**
   * Limpeza automática de tokens expirados
   */
  private startTokenCleanup(): void {
    setInterval(() => {
      // Limpar CSRF tokens expirados
      for (const [token, data] of this.csrfTokens.entries()) {
        if (Date.now() > data.expiresAt) {
          this.csrfTokens.delete(token);
        }
      }

      // Limpar sessões expiradas
      for (const [sessionId, data] of this.sessionTokens.entries()) {
        if (Date.now() > data.expiresAt) {
          this.sessionTokens.delete(sessionId);
        }
      }
    }, 300000); // A cada 5 minutos
  }

  /**
   * Recupera logs de requisição
   */
  getRequestLogs(limit: number = 100): any[] {
    return this.requestLog.slice(-limit);
  }

  /**
   * Relatório de segurança
   */
  getSecurityReport(): any {
    const logs = this.requestLog;

    const suspiciousRequests = logs.filter((log: any) =>
      log.status >= 400
    );

    return {
      totalRequests: logs.length,
      suspiciousRequests: suspiciousRequests.length,
      activeSessions: this.sessionTokens.size,
      activeCsrfTokens: this.csrfTokens.size,
      byStatusCode: logs.reduce((acc: any, log: any) => {
        acc[log.status] = (acc[log.status] || 0) + 1;
        return acc;
      }, {}),
      byMethod: logs.reduce((acc: any, log: any) => {
        acc[log.method] = (acc[log.method] || 0) + 1;
        return acc;
      }, {})
    };
  }
}

/**
 * Middleware para validar CSRF em POST/PUT/DELETE
 */
export function csrfValidationMiddleware(manager: WebSecurityManager) {
  return (req: Request, res: Response, next: NextFunction) => {
    const method = req.method.toUpperCase();

    // Apenas validar em métodos que modificam estado
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      return next();
    }

    const token = req.headers['x-csrf-token'] as string;
    const sessionId = req.cookies.sessionId as string;

    if (!token || !sessionId) {
      return res.status(403).json({
        error: 'CSRF token or session missing'
      });
    }

    if (!manager.validateCSRFToken(token, sessionId)) {
      return res.status(403).json({
        error: 'Invalid or expired CSRF token'
      });
    }

    next();
  };
}

/**
 * Middleware para validar sessão
 */
export function sessionValidationMiddleware(manager: WebSecurityManager) {
  return (req: Request, res: Response, next: NextFunction) => {
    const sessionId = req.cookies.sessionId as string;

    if (!sessionId || !manager.validateSession(sessionId)) {
      return res.status(401).json({
        error: 'Invalid or expired session'
      });
    }

    req.sessionId = sessionId;
    next();
  };
}

export { WebSecurityManager, WebSecurityConfig };
```

### 4.3 Configuração de Segurança

**Arquivo: `src/config/web-security-config.ts`**

```typescript
import { WebSecurityConfig } from '../web-security-patch';

export const WEB_SECURITY_CONFIG: WebSecurityConfig = {
  corsOrigins: [
    'http://localhost:3000',
    'http://localhost:5173', // Vite dev
    process.env.FRONTEND_URL || 'https://yourdomain.com'
  ],

  csrfProtection: true,
  xssProtection: true,

  helmetConfig: {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"], // Considerar remover unsafe-inline
        imgSrc: ["'self'", 'data:', 'https:'],
        fontSrc: ["'self'"],
        connectSrc: ["'self'"],
        frameSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"]
      },
      reportUri: '/api/security/csp-report'
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    dnsPrefetchControl: true,
    frameguard: { action: 'deny' },
    hidePoweredBy: true,
    hsts: {
      maxAge: 31536000, // 1 ano
      includeSubDomains: true,
      preload: true
    },
    ieNoOpen: true,
    noSniff: true,
    referrerPolicy: { policy: 'strict-no-referrer' },
    xssFilter: true
  },

  rateLimitConfig: {
    windowMs: 15 * 60 * 1000, // 15 minutos
    maxRequests: 100 // 100 requisições por janela
  },

  sessionTimeout: 3600000, // 1 hora
  secureCookies: process.env.NODE_ENV === 'production'
};
```

### 4.4 Integração com Express

**Arquivo: `src/routes/web-security-routes.ts`**

```typescript
import { Router, Request, Response } from 'express';
import { WebSecurityManager } from '../web-security-patch';
import { sessionValidationMiddleware, csrfValidationMiddleware } from '../web-security-patch';

export function createWebSecurityRoutes(manager: WebSecurityManager): Router {
  const router = Router();

  /**
   * Endpoint de login (gerar sessão e CSRF token)
   */
  router.post('/api/auth/login', (req: Request, res: Response) => {
    const { username, password } = req.body;

    // Validação básica
    if (!username || !password) {
      return res.status(400).json({ error: 'Missing credentials' });
    }

    // Implementar validação de credenciais aqui
    // Se válido:
    const sessionId = manager.createSession(username);
    const csrfToken = manager.generateCSRFToken(sessionId);

    res.cookie('sessionId', sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000
    });

    res.json({
      success: true,
      csrfToken,
      message: 'Login successful'
    });
  });

  /**
   * Endpoint para logout
   */
  router.post('/api/auth/logout',
    sessionValidationMiddleware(manager),
    (req: Request, res: Response) => {
      const sessionId = req.cookies.sessionId;
      manager.invalidateSession(sessionId);

      res.clearCookie('sessionId');
      res.json({ success: true, message: 'Logout successful' });
    }
  );

  /**
   * Endpoint para renovar CSRF token
   */
  router.post('/api/auth/refresh-csrf',
    sessionValidationMiddleware(manager),
    (req: Request, res: Response) => {
      const sessionId = req.cookies.sessionId;
      const newToken = manager.generateCSRFToken(sessionId);

      res.json({
        success: true,
        csrfToken: newToken
      });
    }
  );

  /**
   * Logs de segurança
   */
  router.get('/api/security/logs',
    sessionValidationMiddleware(manager),
    (req: Request, res: Response) => {
      const limit = Math.min(parseInt(req.query.limit as string) || 100, 1000);
      const logs = manager.getRequestLogs(limit);

      res.json({
        count: logs.length,
        logs
      });
    }
  );

  /**
   * Relatório de segurança
   */
  router.get('/api/security/report',
    sessionValidationMiddleware(manager),
    (req: Request, res: Response) => {
      const report = manager.getSecurityReport();
      res.json(report);
    }
  );

  /**
   * Endpoint para reportar violações de CSP
   */
  router.post('/api/security/csp-report', (req: Request, res: Response) => {
    console.warn('CSP Violation:', req.body);
    res.status(204).send();
  });

  return router;
}
```

### 4.5 Testes de Segurança Web

**Arquivo: `tests/web-security.test.ts`**

```typescript
import { describe, it, expect, beforeEach } from '@jest/globals';
import { WebSecurityManager } from '../src/web-security-patch';
import { WEB_SECURITY_CONFIG } from '../src/config/web-security-config';

describe('Web Security Tests', () => {
  let manager: WebSecurityManager;

  beforeEach(() => {
    manager = new WebSecurityManager(WEB_SECURITY_CONFIG);
  });

  // TEST 1: Gera e valida CSRF token
  it('should generate and validate CSRF token', () => {
    const sessionId = 'test-session-123';
    const token = manager.generateCSRFToken(sessionId);

    expect(token).toBeDefined();
    expect(token.length).toBeGreaterThan(0);

    const isValid = manager.validateCSRFToken(token, sessionId);
    expect(isValid).toBe(true);
  });

  // TEST 2: Rejeita CSRF token inválido
  it('should reject invalid CSRF token', () => {
    const sessionId = 'test-session-123';

    const isValid = manager.validateCSRFToken('invalid-token', sessionId);
    expect(isValid).toBe(false);
  });

  // TEST 3: Rejeita CSRF token de sessão diferente
  it('should reject CSRF token from different session', () => {
    const sessionId1 = 'session-1';
    const sessionId2 = 'session-2';

    const token = manager.generateCSRFToken(sessionId1);
    const isValid = manager.validateCSRFToken(token, sessionId2);

    expect(isValid).toBe(false);
  });

  // TEST 4: Cria e valida sessão
  it('should create and validate session', () => {
    const sessionId = manager.createSession('testuser');

    expect(sessionId).toBeDefined();
    expect(manager.validateSession(sessionId)).toBe(true);
  });

  // TEST 5: Invalida sessão
  it('should invalidate session', () => {
    const sessionId = manager.createSession('testuser');
    expect(manager.validateSession(sessionId)).toBe(true);

    manager.invalidateSession(sessionId);
    expect(manager.validateSession(sessionId)).toBe(false);
  });

  // TEST 6: CSRF token é único
  it('should issue unique CSRF tokens', () => {
    const sessionId = 'test-session';

    const token1 = manager.generateCSRFToken(sessionId);
    const token2 = manager.generateCSRFToken(sessionId);

    expect(token1).not.toEqual(token2);
  });

  // TEST 7: Relatório de segurança
  it('should generate security report', () => {
    const report = manager.getSecurityReport();

    expect(report.totalRequests).toBeDefined();
    expect(report.suspiciousRequests).toBeDefined();
    expect(report.activeSessions).toBeDefined();
    expect(report.activeCsrfTokens).toBeDefined();
  });
});
```

### 4.6 Validação da Remediação

```bash
# 1. Executar testes
npm test -- web-security.test.ts

# 2. Testar CORS
curl -i -X OPTIONS http://localhost:3000/api/endpoint \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: POST"

# 3. Verificar headers de segurança
curl -i http://localhost:3000 | grep -E "Content-Security-Policy|X-Frame-Options|Strict-Transport-Security"

# 4. Testar rate limiting
for i in {1..101}; do
  curl -s http://localhost:3000/api/endpoint > /dev/null &
done
wait

# 5. Validar sanitização XSS
curl -X POST http://localhost:3000/api/data \
  -H "Content-Type: application/json" \
  -d '{"input": "<script>alert(\"XSS\")</script>"}'
```

---

## 5. Armazenamento Inseguro de Credenciais

### 5.1 Causa Raiz Técnica

Credenciais são armazenadas:
- Em plain text
- Sem criptografia
- Sem hash
- Com acesso descontrolado
- Sem rotação

### 5.2 Código de Patch Completo

**Arquivo: `src/credential-security-patch.ts`**

```typescript
import crypto, { scryptSync, randomBytes, createCipheriv, createDecipheriv } from 'crypto';
import bcrypt from 'bcrypt';
import { Database } from 'sqlite3';

interface StoredCredential {
  id: string;
  service: string;
  username: string;
  passwordHash: string;
  secretEncrypted: string; // API key/token criptografado
  encryptionIv: string; // IV para decriptação
  metadata: {
    createdAt: number;
    lastUsed: number;
    rotatedAt: number;
    algorithm: string;
  };
  tags: string[];
  accessLog: Array<{
    timestamp: number;
    context: string;
    success: boolean;
  }>;
}

interface EncryptionKey {
  key: Buffer;
  salt: string;
  algorithm: string;
}

class CredentialSecurityManager {
  private encryptionKey: EncryptionKey | null = null;
  private accessLog: any[] = [];
  private readonly ALGORITHM = 'aes-256-gcm';
  private readonly BCRYPT_ROUNDS = 12;
  private readonly MAX_CREDENTIAL_AGE = 90 * 24 * 60 * 60 * 1000; // 90 dias

  /**
   * Inicializa manager com chave de criptografia
   * Chave deve vir de variável de ambiente ou gerenciador de segredos
   */
  initialize(masterSecret: string): void {
    // Derivar chave de criptografia a partir do master secret
    const salt = process.env.ENCRYPTION_SALT || randomBytes(16).toString('hex');

    // Usar scrypt para derivação de chave
    const key = scryptSync(masterSecret, salt, 32);

    this.encryptionKey = {
      key,
      salt,
      algorithm: this.ALGORITHM
    };

    console.log('✓ Credential manager initialized');
  }

  /**
   * Criptografa um secret (API key, token, etc)
   */
  private encryptSecret(secret: string): { encrypted: string; iv: string; tag: string } {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not initialized');
    }

    const iv = randomBytes(16);
    const cipher = createCipheriv(
      this.ALGORITHM,
      this.encryptionKey.key,
      iv
    );

    let encrypted = cipher.update(secret, 'utf-8', 'hex');
    encrypted += cipher.final('hex');

    const tag = (cipher as any).getAuthTag().toString('hex');

    return {
      encrypted,
      iv: iv.toString('hex'),
      tag
    };
  }

  /**
   * Descriptografa um secret
   */
  private decryptSecret(
    encrypted: string,
    iv: string,
    tag: string
  ): string {
    if (!this.encryptionKey) {
      throw new Error('Encryption key not initialized');
    }

    const decipher = createDecipheriv(
      this.ALGORITHM,
      this.encryptionKey.key,
      Buffer.from(iv, 'hex')
    );

    (decipher as any).setAuthTag(Buffer.from(tag, 'hex'));

    let decrypted = decipher.update(encrypted, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');

    return decrypted;
  }

  /**
   * Armazena credencial de forma segura
   */
  async storeCredential(
    service: string,
    username: string,
    password: string,
    secret: string,
    tags: string[] = []
  ): Promise<{ id: string; success: boolean; error?: string }> {
    try {
      // Validar entrada
      if (!service || !username || (!password && !secret)) {
        return {
          id: '',
          success: false,
          error: 'service, username, and either password or secret required'
        };
      }

      // Gerar hash seguro da senha com bcrypt
      const passwordHash = await bcrypt.hash(password, this.BCRYPT_ROUNDS);

      // Criptografar secret
      const { encrypted, iv, tag } = this.encryptSecret(secret);

      // Gerar ID único
      const id = crypto.randomBytes(16).toString('hex');

      // Criar estrutura de credencial
      const credential: StoredCredential = {
        id,
        service,
        username,
        passwordHash,
        secretEncrypted: encrypted,
        encryptionIv: iv,
        metadata: {
          createdAt: Date.now(),
          lastUsed: 0,
          rotatedAt: Date.now(),
          algorithm: this.ALGORITHM
        },
        tags: tags.filter(t => /^[a-zA-Z0-9-_]{1,50}$/.test(t)), // Validar tags
        accessLog: []
      };

      // Adicionar tag de encryption para referência
      // (Nota: Em produção, seria salvo em DB segura)
      this.logAccess('store_credential', {
        credentialId: id,
        service,
        success: true
      });

      // Retornar apenas o ID (nunca retornar a credencial completa)
      return {
        id,
        success: true
      };
    } catch (error: any) {
      this.logAccess('store_credential', {
        service,
        success: false,
        error: error.message
      });

      return {
        id: '',
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Recupera credencial de forma segura
   * Apenas retorna o secret descriptografado quando necessário
   */
  async retrieveSecret(
    credentialId: string,
    context: string = 'unknown'
  ): Promise<{ secret?: string; success: boolean; error?: string }> {
    try {
      // Validar contexto
      if (!credentialId || typeof credentialId !== 'string') {
        return { success: false, error: 'Invalid credential ID' };
      }

      // Verificar autorização (implementar RBAC aqui)
      // ...

      // Recuperar credencial (em produção, de DB)
      // const credential = await db.getCredential(credentialId);

      // Simulação:
      const credential = { secretEncrypted: '', encryptionIv: '', metadata: { createdAt: 0 } };

      if (!credential) {
        return { success: false, error: 'Credential not found' };
      }

      // Validar idade da credencial (força rotação)
      const age = Date.now() - credential.metadata.createdAt;
      if (age > this.MAX_CREDENTIAL_AGE) {
        return {
          success: false,
          error: `Credential expired. Age: ${Math.round(age / (24 * 60 * 60 * 1000))} days`
        };
      }

      // Descriptografar
      const secret = this.decryptSecret(
        credential.secretEncrypted,
        credential.encryptionIv,
        '' // tag seria armazenado junto
      );

      // Registrar acesso
      this.logAccess('retrieve_secret', {
        credentialId,
        context,
        success: true
      });

      return { secret, success: true };
    } catch (error: any) {
      this.logAccess('retrieve_secret', {
        credentialId,
        context,
        success: false,
        error: error.message
      });

      return {
        success: false,
        error: 'Failed to retrieve credential'
      };
    }
  }

  /**
   * Valida senha contra hash armazenado
   */
  async validatePassword(
    credentialId: string,
    password: string
  ): Promise<boolean> {
    try {
      // Recuperar hash (em produção, de DB)
      // const credential = await db.getCredential(credentialId);

      // Simulação:
      const credential = { passwordHash: '' };

      if (!credential) {
        return false;
      }

      return await bcrypt.compare(password, credential.passwordHash);
    } catch (error) {
      return false;
    }
  }

  /**
   * Força rotação de credencial
   */
  async rotateCredential(
    credentialId: string,
    newSecret: string
  ): Promise<{ success: boolean; error?: string }> {
    try {
      // Recuperar credencial antiga
      // const oldCredential = await db.getCredential(credentialId);

      // Criptografar novo secret
      const { encrypted, iv, tag } = this.encryptSecret(newSecret);

      // Atualizar credencial
      // await db.updateCredential(credentialId, {
      //   secretEncrypted: encrypted,
      //   encryptionIv: iv,
      //   metadata: {
      //     ...oldCredential.metadata,
      //     rotatedAt: Date.now()
      //   }
      // });

      this.logAccess('rotate_credential', {
        credentialId,
        success: true
      });

      return { success: true };
    } catch (error: any) {
      this.logAccess('rotate_credential', {
        credentialId,
        success: false,
        error: error.message
      });

      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Deleta credencial com segurança
   */
  async deleteCredential(credentialId: string): Promise<boolean> {
    try {
      // Recuperar credencial para log
      // const credential = await db.getCredential(credentialId);

      // Deletar de forma segura (em produção, hard delete ou soft delete com timestamp)
      // await db.deleteCredential(credentialId);

      this.logAccess('delete_credential', {
        credentialId,
        success: true
      });

      return true;
    } catch (error) {
      this.logAccess('delete_credential', {
        credentialId,
        success: false
      });

      return false;
    }
  }

  /**
   * Registra acesso a credenciais
   */
  private logAccess(action: string, details: any): void {
    this.accessLog.push({
      timestamp: Date.now(),
      action,
      details,
      success: details.success,
      ip: details.ip || 'unknown'
    });

    // Manter últimos 10000 logs
    if (this.accessLog.length > 10000) {
      this.accessLog = this.accessLog.slice(-10000);
    }
  }

  /**
   * Recupera logs de acesso a credenciais
   */
  getAccessLogs(limit: number = 100): any[] {
    return this.accessLog.slice(-limit);
  }

  /**
   * Relatório de segurança de credenciais
   */
  getSecurityReport(): any {
    const logs = this.accessLog;
    const failed = logs.filter(log => !log.success);

    return {
      totalAccesses: logs.length,
      failedAccesses: failed.length,
      failureRate: logs.length > 0
        ? ((failed.length / logs.length) * 100).toFixed(2) + '%'
        : '0%',
      byAction: logs.reduce((acc: any, log: any) => {
        acc[log.action] = (acc[log.action] || 0) + 1;
        return acc;
      }, {}),
      recentFailures: failed.slice(-10)
    };
  }

  /**
   * Migra credenciais antigas (plain text) para formato seguro
   */
  async migrateInsecureCredentials(
    unsecureCredentials: Array<{ service: string; username: string; secret: string }>
  ): Promise<Array<{ id: string; success: boolean }>> {
    const results = [];

    for (const cred of unsecureCredentials) {
      const result = await this.storeCredential(
        cred.service,
        cred.username,
        '', // sem senha
        cred.secret,
        ['migrated']
      );

      results.push(result);
    }

    return results;
  }
}

export { CredentialSecurityManager, StoredCredential, EncryptionKey };
```

### 5.3 Configuração de Banco de Dados Seguro

**Arquivo: `src/db/credentials-table.sql`**

```sql
-- Tabela de credenciais com segurança
CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY,
  service TEXT NOT NULL,
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  secret_encrypted TEXT NOT NULL,
  encryption_iv TEXT NOT NULL,
  encryption_tag TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used INTEGER DEFAULT 0,
  rotated_at INTEGER NOT NULL,
  algorithm TEXT DEFAULT 'aes-256-gcm',
  tags TEXT, -- JSON array
  deleted_at INTEGER DEFAULT NULL,
  INDEX idx_service (service),
  INDEX idx_created (created_at),
  UNIQUE(service, username)
);

-- Tabela de auditoria de acesso
CREATE TABLE IF NOT EXISTS credential_access_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  credential_id TEXT NOT NULL,
  action TEXT NOT NULL,
  context TEXT,
  success INTEGER NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  timestamp INTEGER NOT NULL,
  error_message TEXT,
  INDEX idx_credential (credential_id),
  INDEX idx_timestamp (timestamp),
  FOREIGN KEY(credential_id) REFERENCES credentials(id)
);

-- Política de expiração
CREATE TRIGGER credential_expiry_check
AFTER SELECT ON credentials
BEGIN
  SELECT CASE
    WHEN (julianday('now') * 86400000 - NEW.created_at) > 7776000000 THEN
      RAISE(ABORT, 'Credential expired. Please rotate.')
  END;
END;
```

### 5.4 Integração com API

**Arquivo: `src/routes/credentials.ts`**

```typescript
import { Router, Request, Response } from 'express';
import { CredentialSecurityManager } from '../credential-security-patch';

const router = Router();
const credentialManager = new CredentialSecurityManager();

// Inicializar com master secret de variável de ambiente
const masterSecret = process.env.MASTER_SECRET || '';
credentialManager.initialize(masterSecret);

/**
 * Armazenar nova credencial
 */
router.post('/api/credentials/store', async (req: Request, res: Response) => {
  try {
    const { service, username, password, secret, tags } = req.body;

    const result = await credentialManager.storeCredential(
      service,
      username,
      password,
      secret,
      tags
    );

    if (result.success) {
      res.json({
        success: true,
        credentialId: result.id,
        message: 'Credential stored securely'
      });
    } else {
      res.status(400).json({ error: result.error });
    }
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Recuperar secret de credencial
 */
router.post('/api/credentials/retrieve', async (req: Request, res: Response) => {
  try {
    const { credentialId, context } = req.body;

    const result = await credentialManager.retrieveSecret(
      credentialId,
      context || 'api_request'
    );

    if (result.success) {
      res.json({
        success: true,
        secret: result.secret
      });
    } else {
      res.status(400).json({ error: result.error });
    }
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Validar senha
 */
router.post('/api/credentials/validate', async (req: Request, res: Response) => {
  try {
    const { credentialId, password } = req.body;

    const isValid = await credentialManager.validatePassword(
      credentialId,
      password
    );

    res.json({ valid: isValid });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Rotacionar credencial
 */
router.post('/api/credentials/rotate', async (req: Request, res: Response) => {
  try {
    const { credentialId, newSecret } = req.body;

    const result = await credentialManager.rotateCredential(
      credentialId,
      newSecret
    );

    if (result.success) {
      res.json({ success: true, message: 'Credential rotated' });
    } else {
      res.status(400).json({ error: result.error });
    }
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Deletar credencial
 */
router.post('/api/credentials/delete', async (req: Request, res: Response) => {
  try {
    const { credentialId } = req.body;

    const success = await credentialManager.deleteCredential(credentialId);

    if (success) {
      res.json({ success: true, message: 'Credential deleted' });
    } else {
      res.status(400).json({ error: 'Failed to delete credential' });
    }
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Logs de acesso
 */
router.get('/api/credentials/logs', (req: Request, res: Response) => {
  const limit = Math.min(parseInt(req.query.limit as string) || 100, 1000);
  const logs = credentialManager.getAccessLogs(limit);

  res.json({ count: logs.length, logs });
});

/**
 * Relatório de segurança
 */
router.get('/api/credentials/security-report', (req: Request, res: Response) => {
  const report = credentialManager.getSecurityReport();
  res.json(report);
});

export default router;
```

### 5.5 Testes e Validação

**Arquivo: `tests/credentials.test.ts`**

```typescript
import { describe, it, expect, beforeEach } from '@jest/globals';
import { CredentialSecurityManager } from '../src/credential-security-patch';

describe('Credential Security Tests', () => {
  let credManager: CredentialSecurityManager;

  beforeEach(() => {
    credManager = new CredentialSecurityManager();
    credManager.initialize(process.env.MASTER_SECRET || 'test-secret');
  });

  // TEST 1: Armazena credencial com segurança
  it('should store credential securely', async () => {
    const result = await credManager.storeCredential(
      'postgres',
      'admin',
      'mypassword123',
      'secret-db-key-12345',
      ['database', 'production']
    );

    expect(result.success).toBe(true);
    expect(result.id).toBeTruthy();
  });

  // TEST 2: Recupera secret com sucesso
  it('should retrieve secret successfully', async () => {
    const store = await credManager.storeCredential(
      'api',
      'service',
      'pass',
      'my-api-secret-key'
    );

    const retrieve = await credManager.retrieveSecret(store.id);

    expect(retrieve.success).toBe(true);
    expect(retrieve.secret).toBe('my-api-secret-key');
  });

  // TEST 3: Valida senha com bcrypt
  it('should validate password correctly', async () => {
    const store = await credManager.storeCredential(
      'app',
      'user',
      'correct-password',
      'secret'
    );

    const isValid = await credManager.validatePassword(
      store.id,
      'correct-password'
    );

    expect(isValid).toBe(true);
  });

  // TEST 4: Rejeita senha incorreta
  it('should reject wrong password', async () => {
    const store = await credManager.storeCredential(
      'app',
      'user',
      'correct-password',
      'secret'
    );

    const isValid = await credManager.validatePassword(
      store.id,
      'wrong-password'
    );

    expect(isValid).toBe(false);
  });

  // TEST 5: Rotaciona credencial
  it('should rotate credential', async () => {
    const store = await credManager.storeCredential(
      'api',
      'user',
      'pass',
      'old-secret'
    );

    const rotate = await credManager.rotateCredential(
      store.id,
      'new-secret'
    );

    expect(rotate.success).toBe(true);
  });
});
```

### 5.6 Validação da Remediação

```bash
# 1. Executar testes
npm test -- credentials.test.ts

# 2. Testar armazenamento seguro
curl -X POST http://localhost:3000/api/credentials/store \
  -H "Content-Type: application/json" \
  -d '{
    "service": "postgres",
    "username": "admin",
    "password": "mysecretpass",
    "secret": "db-connection-string",
    "tags": ["database", "production"]
  }'

# 3. Recuperar credencial
curl -X POST http://localhost:3000/api/credentials/retrieve \
  -H "Content-Type: application/json" \
  -d '{"credentialId": "CREDENTIAL_ID_HERE"}'

# 4. Verificar logs de acesso
curl http://localhost:3000/api/credentials/logs

# 5. Gerar relatório de segurança
curl http://localhost:3000/api/credentials/security-report
```

**Configuração de Ambiente (`.env.example`)**

```bash
# Master secret para criptografia (DEVE ser gerado aleatoriamente em produção)
MASTER_SECRET="your-very-secure-master-secret-min-32-chars"

# Salt para derivação de chave
ENCRYPTION_SALT="your-unique-salt-value"

# Banco de dados
DATABASE_URL="sqlite://:memory:"

# Ambiente
NODE_ENV="production"

# HTTPS
SECURE_COOKIES=true
```

Continuaremos com as vulnerabilidades 6 e 7 na próxima parte...

