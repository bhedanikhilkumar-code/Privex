import { ModelIntegrityVerifier } from './model-metadata';
import { ModelMetadata, ModelProvider } from '../types';

export class ModelLoader {
  private registeredProviders: Map<string, ModelProvider> = new Map();
  private loadedProviders: Map<string, ModelProvider> = new Map();

  public registerProvider(provider: ModelProvider): void {
    this.registeredProviders.set(provider.id, provider);
  }

  public getProvider(id: string): ModelProvider | undefined {
    return this.loadedProviders.get(id) || this.registeredProviders.get(id);
  }

  public isLoaded(id: string): boolean {
    return this.loadedProviders.has(id);
  }

  /**
   * Safely loads a model buffer by verifying its cryptographic integrity before initializing.
   */
  public async loadModelFromBuffer(
    buffer: Uint8Array | Buffer,
    metadata: ModelMetadata,
    providerFactory: (meta: ModelMetadata, buf: Uint8Array | Buffer) => ModelProvider
  ): Promise<{ success: boolean; provider?: ModelProvider; error?: string }> {
    // 1. Verify buffer integrity
    const verification = ModelIntegrityVerifier.verifyModelBuffer(buffer, metadata);
    if (!verification.valid) {
      return { success: false, error: verification.error };
    }

    try {
      const provider = providerFactory(metadata, buffer);
      const loaded = await provider.load();
      if (!loaded) {
        return { success: false, error: 'ModelInitializationFailedError: provider failed to initialize' };
      }

      this.registeredProviders.set(provider.id, provider);
      this.loadedProviders.set(provider.id, provider);
      return { success: true, provider };
    } catch (err: any) {
      return { success: false, error: `ModelLoadException: ${err.message}` };
    }
  }

  /**
   * Activates an already registered provider safely.
   */
  public async activateProvider(id: string): Promise<{ success: boolean; error?: string }> {
    const provider = this.registeredProviders.get(id);
    if (!provider) {
      return { success: false, error: `ProviderNotFoundError: provider '${id}' is not registered` };
    }

    try {
      const ok = await provider.load();
      if (ok) {
        this.loadedProviders.set(id, provider);
        return { success: true };
      }
      return { success: false, error: 'InitializationFailed' };
    } catch (err: any) {
      return { success: false, error: err.message };
    }
  }

  /**
   * Unloads and frees in-memory provider resources.
   */
  public async unloadProvider(id: string): Promise<void> {
    const provider = this.loadedProviders.get(id);
    if (provider) {
      await provider.unload();
      this.loadedProviders.delete(id);
    }
  }

  public getLoadedModelCount(): number {
    return this.loadedProviders.size;
  }
}
