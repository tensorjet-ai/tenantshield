import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

describe('TenantShield MCP stdio server', () => {
  it('keeps stdout parseable and advertises the three tools', async () => {
    const child = spawn(process.execPath, [resolve('packages/mcp/dist/index.js')], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      output += chunk;
    });
    await new Promise<void>((resolvePromise, reject) => {
      const timeout = setTimeout(() => reject(new Error('MCP server did not respond')), 2_000);
      const check = () => {
        if (output.trim().split('\n').length >= 2) {
          clearTimeout(timeout);
          child.kill();
          resolvePromise();
        }
      };
      child.stdout.on('data', check);
      child.once('error', reject);
      child.stdin.write(
        `${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} })}\n`,
      );
      child.stdin.write(
        `${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} })}\n`,
      );
    });
    const responses = output
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as { id: number; result: { tools?: { name: string }[] } });
    expect(responses.map((response) => response.id)).toEqual([1, 2]);
    expect(responses[1]?.result.tools?.map((tool) => tool.name)).toEqual([
      'inspect_rls_matrix',
      'verify_migration_safety',
      'simulate_tenant_access',
    ]);
  });
});
