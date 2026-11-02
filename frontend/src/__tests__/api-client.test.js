describe('API base URL', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it('uses the default Compose backend port when no URL is configured', async () => {
    vi.stubEnv('VITE_API_BASE_URL', '');
    vi.resetModules();

    const { BASE_URL } = await import('../api/client');

    expect(BASE_URL).toBe('http://localhost:8081');
  });

  it('uses the configured backend URL when provided', async () => {
    vi.stubEnv('VITE_API_BASE_URL', 'http://localhost:8080');
    vi.resetModules();

    const { BASE_URL } = await import('../api/client');

    expect(BASE_URL).toBe('http://localhost:8080');
  });

  it('requests scan analytics from the authorized scan-scoped endpoint', async () => {
    vi.stubEnv('VITE_API_BASE_URL', '');
    vi.resetModules();
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({ success: true, data: { scanId: 17 } }),
    });
    const { scanApi } = await import('../api/client');

    await expect(scanApi.getScanAnalytics(17)).resolves.toMatchObject({
      data: { scanId: 17 },
    });
    expect(fetchSpy).toHaveBeenCalledWith(
      'http://localhost:8081/api/scans/17/analytics',
      expect.objectContaining({ method: 'GET', credentials: 'include' }),
    );
  });
});
