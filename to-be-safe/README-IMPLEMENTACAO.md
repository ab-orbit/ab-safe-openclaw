# Implementação de Patches de Segurança OpenClaw - Guia Prático

## Visão Geral

Este guia contém patches de código funcionais para remediar as 7 vulnerabilidades críticas do OpenClaw. Cada patch inclui:

- ✓ Análise detalhada da vulnerabilidade
- ✓ Código completo e testável
- ✓ Testes automatizados
- ✓ Exemplos de uso
- ✓ Validação de remediação

## Arquivos do Guia

1. **guia-openclaw-vulnerabilidades-parte-1.md** (150KB)
   - CVE-2026-25253: RCE via WebSocket
   - Skills Maliciosos: Validação e Sandbox
   - Vulnerabilidades em Skills: Controle de Permissões

2. **guia-openclaw-vulnerabilidades-parte-2.md** (120KB)
   - Interface Web Desprotegida: CSRF, XSS, CORS
   - Armazenamento Inseguro de Credenciais: Criptografia
   - (Continuação)

3. **guia-openclaw-vulnerabilidades-parte-3.md** (100KB)
   - Prompt Injection: Detecção e Sanitização
   - Interfaces Administrativas Expostas: RBAC e Auditoria

## Estrutura de Implementação Recomendada

```
projeto-openclaw/
├── src/
│   ├── websocket-security-patch.ts
│   ├── skill-security-patch.ts
│   ├── skill-permissions-patch.ts
│   ├── web-security-patch.ts
│   ├── credential-security-patch.ts
│   ├── prompt-injection-patch.ts
│   ├── admin-security-patch.ts
│   ├── config/
│   │   ├── websocket-config.ts
│   │   └── web-security-config.ts
│   ├── routes/
│   │   ├── skills.ts
│   │   ├── permissions.ts
│   │   ├── credentials.ts
│   │   ├── prompt-safety.ts
│   │   ├── web-security-routes.ts
│   │   └── admin.ts
│   ├── db/
│   │   ├── credentials-table.sql
│   │   └── admin-audit-schema.sql
│   └── server.ts
├── tests/
│   ├── websocket-security.test.ts
│   ├── skill-security.test.ts
│   ├── permissions.test.ts
│   ├── web-security.test.ts
│   ├── credentials.test.ts
│   ├── prompt-injection.test.ts
│   └── admin-security.test.ts
├── .env.example
├── .env.production
├── package.json
└── README.md
```

## Passo a Passo de Implementação

### 1. Preparação

```bash
# Clonar ou fazer fork do repositório OpenClaw
git clone https://github.com/openclaw/openclaw.git
cd openclaw

# Instalar dependências necessárias
npm install --save \
  helmet \
  cors \
  express-rate-limit \
  csurf \
  cookie-parser \
  bcrypt \
  vm2 \
  ajv \
  xss \
  validator \
  compromise

# Instalar devDependencies
npm install --save-dev \
  @jest/globals \
  jest \
  @types/jest \
  ts-jest
```

### 2. Configurar Jest

**jest.config.js**

```javascript
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests', '<rootDir>/src'],
  testMatch: ['**/*.test.ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/config/**'
  ],
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 70,
      lines: 70,
      statements: 70
    }
  }
};
```

### 3. Configurar TypeScript

**tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "strictFunctionTypes": true,
    "strictBindCallApply": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

### 4. Implementar Patches (Ordem Recomendada)

#### Fase 1: Segurança Base (Semana 1)

1. **WebSocket Security (CVE-2026-25253)**
   - Copiar `websocket-security-patch.ts` para `src/`
   - Copiar `websocket-config.ts` para `src/config/`
   - Executar: `npm test -- websocket-security.test.ts`
   - Integrar com `server.ts`

2. **Credential Security**
   - Copiar `credential-security-patch.ts` para `src/`
   - Criar tabelas: `npm run migrate:credentials`
   - Executar: `npm test -- credentials.test.ts`
   - Integrar com API

#### Fase 2: Validação de Input (Semana 2)

3. **Web Security (CSRF/XSS/CORS)**
   - Copiar `web-security-patch.ts` para `src/`
   - Integrar middleware no `server.ts`
   - Executar: `npm test -- web-security.test.ts`

4. **Prompt Injection**
   - Copiar `prompt-injection-patch.ts` para `src/`
   - Executar: `npm test -- prompt-injection.test.ts`
   - Integrar antes de chamar LLM

#### Fase 3: Controle de Skills (Semana 3)

5. **Skill Security**
   - Copiar `skill-security-patch.ts` para `src/`
   - Executar: `npm test -- skill-security.test.ts`

6. **Skill Permissions**
   - Copiar `skill-permissions-patch.ts` para `src/`
   - Executar: `npm test -- permissions.test.ts`

#### Fase 4: Auditoria e Admin (Semana 4)

7. **Admin Security**
   - Copiar `admin-security-patch.ts` para `src/`
   - Criar tabelas de auditoria
   - Executar: `npm test -- admin-security.test.ts`
   - Proteger endpoints admin

### 5. Integração com Aplicação Existente

**src/server.ts** (Exemplo de integração completa)

```typescript
import express from 'express';
import { createServer } from 'http';
import { WebSecurityManager, configureExpress } from './web-security-patch';
import { setupSecureWebSocketServer } from './websocket-security-patch';
import { WEB_SECURITY_CONFIG } from './config/web-security-config';
import { WEBSOCKET_SECURITY_CONFIG } from './config/websocket-config';

import webSecurityRoutes from './routes/web-security-routes';
import credentialRoutes from './routes/credentials';
import skillRoutes from './routes/skills';
import permissionRoutes from './routes/permissions';
import promptSafetyRoutes from './routes/prompt-safety';
import { adminRouter } from './routes/admin';

const app = express();
const httpServer = createServer(app);

// 1. Configurar segurança web
const webSecManager = new WebSecurityManager(WEB_SECURITY_CONFIG);
webSecManager.configureExpress(app);

// 2. Configurar WebSocket seguro
const wss = setupSecureWebSocketServer(httpServer, WEBSOCKET_SECURITY_CONFIG);

// 3. Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// 4. Registrar rotas seguras
app.use(webSecurityRoutes);
app.use(credentialRoutes);
app.use(skillRoutes);
app.use(permissionRoutes);
app.use(promptSafetyRoutes);
app.use(adminRouter);

// 5. Error handling
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    requestId: req.id
  });
});

const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
  console.log(`✓ Server running on port ${PORT}`);
  console.log(`✓ WebSocket security enabled`);
  console.log(`✓ CSRF protection enabled`);
  console.log(`✓ Admin panel secured`);
});
```

### 6. Testes de Segurança

```bash
# Rodar todos os testes de segurança
npm test

# Com coverage
npm test -- --coverage

# Testes específicos
npm test -- websocket-security.test.ts
npm test -- credential

# Watch mode para desenvolvimento
npm test -- --watch
```

### 7. Validação em Produção

```bash
# Build TypeScript
npm run build

# Verificar vulnerabilidades de dependências
npm audit

# Executar testes de segurança
npm run test:security

# SAST (Static Application Security Testing)
npm run scan

# Executar servidor em modo seguro
NODE_ENV=production npm start
```

## Scripts package.json

```json
{
  "scripts": {
    "build": "tsc",
    "start": "node dist/server.js",
    "dev": "ts-node src/server.ts",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "test:security": "jest --testPathPattern='.*security.*'",
    "lint": "eslint src/**/*.ts",
    "migrate:credentials": "node scripts/migrate-credentials.js",
    "scan": "npm audit && npm run lint",
    "security-report": "node scripts/generate-security-report.js"
  }
}
```

## Variáveis de Ambiente

Criar `.env.production`:

```bash
# Ambiente
NODE_ENV=production
DEBUG=false

# Servidor
PORT=3000
HOSTNAME=0.0.0.0

# SSL/TLS
HTTPS=true
CERT_PATH=/etc/ssl/certs/server.crt
KEY_PATH=/etc/ssl/private/server.key

# Frontend
FRONTEND_URL=https://yourdomain.com
ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com

# WebSocket
WEBSOCKET_TIMEOUT=60000
MAX_CONNECTIONS=1000
RATE_LIMIT_PER_IP=100

# Segurança
MASTER_SECRET=<random-32-chars-min>
ENCRYPTION_SALT=<unique-salt>
SECURE_COOKIES=true
SESSION_TIMEOUT=3600000

# Admin
ADMIN_IPS=192.168.1.1,203.0.113.5
ADMIN_MFA=true
AUDIT_ALL_ACTIONS=true

# Banco de dados
DATABASE_URL=postgresql://user:password@db.example.com:5432/openclaw
DB_ENCRYPT=true

# Logging
LOG_LEVEL=info
LOG_FILE=/var/log/openclaw/app.log
AUDIT_LOG_FILE=/var/log/openclaw/audit.log

# Recursos
MAX_SKILL_MEMORY=134217728
MAX_EXECUTION_TIME=30000
MAX_PROMPT_LENGTH=50000

# Rotação de credenciais
CREDENTIAL_MAX_AGE=7776000000
CREDENTIAL_ROTATION_INTERVAL=604800000
```

## Monitoramento em Produção

### Métricas de Segurança

```bash
# Verificar logs de tentativas de injection
tail -f /var/log/openclaw/audit.log | grep -i "injection\|failed\|blocked"

# Monitorar contas lockadas
curl http://localhost:3000/api/admin/security-report

# Verificar credenciais em risco
curl http://localhost:3000/api/credentials/security-report

# Relatório de WebSocket
curl http://localhost:3000/api/security/report
```

### Alertas Recomendados

1. **Múltiplas tentativas falhadas de login admin** (> 5 em 5 min)
2. **Injeção de prompt detectada** (qualquer)
3. **Sessão hijacking** (IP mismatch)
4. **Acesso a credenciais sensíveis** (cada acesso)
5. **Ações admin críticas** (config changes, deletions)
6. **Rate limiting ativado** (> 90% do limite)

## Troubleshooting

### WebSocket não conecta
```bash
# Verificar headers
curl -i -N -H "Origin: http://localhost:3000" \
  http://localhost:3000/ws

# Logs de rejeição
grep "WebSocket connection rejected" logs/*.log
```

### Credenciais não decriptam
```bash
# Verificar MASTER_SECRET configurado
echo $MASTER_SECRET

# Verificar ENCRYPTION_SALT
echo $ENCRYPTION_SALT

# Reencriptar credenciais
npm run migrate:credentials
```

### Admin panel inacessível
```bash
# Verificar whitelist de IPs
curl -X GET http://localhost:3000/api/admin/security-report

# Resetar se necessário (apenas em emergência)
npm run admin:reset
```

## Performance e Escalabilidade

### Otimizações

1. **Rate Limiting**: Ajustar `rateLimitConfig.maxRequests`
2. **Timeouts**: Aumentar para skills complexos
3. **Memory**: Monitorar credenciais em cache
4. **Database**: Arquivar logs antigos
5. **WebSocket**: Use Redis para múltiplas instâncias

### Teste de Carga

```bash
# Teste de WebSocket
npm run test:load -- --connections 1000 --duration 60

# Teste de credenciais
npm run test:load:credentials -- --operations 10000

# Teste de prompts
npm run test:load:prompts -- --payloads 5000
```

## Conformidade e Auditoria

### Checklist de Compliance

- [ ] Todos os testes passando
- [ ] Cobertura de código > 70%
- [ ] Sem vulnerabilidades conhecidas (`npm audit`)
- [ ] Logs de auditoria habilitados
- [ ] Backup de credenciais funcional
- [ ] Rotação de credenciais agendada
- [ ] MFA admin habilitado
- [ ] HTTPS configurado
- [ ] Headers de segurança presentes
- [ ] Documentação atualizada

### Relatório de Segurança

Gerar relatório periodicamente:

```bash
npm run security-report > reports/security-$(date +%Y-%m-%d).json
```

## Suporte e Contribuições

Para dúvidas ou melhorias:
1. Verificar documentação em cada arquivo
2. Executar testes para validação
3. Seguir padrões de código existentes
4. Submeter PR com testes

## Referências Adicionais

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Node.js Security Checklist](https://nodejs.org/en/learn/getting-started/security-best-practices)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CWE Top 25](https://cwe.mitre.org/top25/)

---

**Versão**: 1.0
**Data**: 2026-02-03
**Autores**: Security Research Team
**Status**: ✓ Pronto para implementação
