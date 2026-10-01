import { InferenceRequest, InferenceResult, ModelMetadata, ModelProvider } from '../../types';

export abstract class BaseModelProvider implements ModelProvider {
  public abstract readonly id: string;
  public abstract readonly metadata: ModelMetadata;
  protected loaded: boolean = false;

  public abstract load(): Promise<boolean>;

  public isLoaded(): boolean {
    return this.loaded;
  }

  public async unload(): Promise<void> {
    this.loaded = false;
  }

  public abstract infer(request: InferenceRequest): Promise<InferenceResult>;
}
