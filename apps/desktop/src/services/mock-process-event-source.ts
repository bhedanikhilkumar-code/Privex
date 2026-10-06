import { EventEmitter } from 'events';
import {
  IProcessEventSource,
  ProcessCreationEvent,
  ProcessEventSourceStatus
} from '../types/desktop.types';

export class MockProcessEventSource extends EventEmitter implements IProcessEventSource {
  private state: 'INITIALIZING' | 'ACTIVE' | 'ERROR' | 'STOPPED' = 'STOPPED';
  private lastError?: string;
  private eventsObserved = 0;
  private processCreatedCallback?: (event: ProcessCreationEvent) => void;
  private readonly startupBuffer: ProcessCreationEvent[] = [];
  public startCallCount = 0;
  public stopCallCount = 0;

  public getStatus(): ProcessEventSourceStatus {
    return {
      state: this.state,
      sourceName: 'MOCK',
      lastError: this.lastError,
      eventsObserved: this.eventsObserved
    };
  }

  public onProcessCreated(callback: (event: ProcessCreationEvent) => void): void {
    this.processCreatedCallback = callback;
    this.flushStartupBuffer();
  }

  public async start(callback?: (event: ProcessCreationEvent) => void): Promise<void> {
    if (callback) {
      this.onProcessCreated(callback);
    }
    this.startCallCount++;
    this.state = 'ACTIVE';
    this.lastError = undefined;
    this.emit('active');
  }

  public async stop(): Promise<void> {
    this.stopCallCount++;
    this.state = 'STOPPED';
    this.startupBuffer.length = 0;
    this.emit('stopped');
  }

  public async dispose(): Promise<void> {
    await this.stop();
    this.processCreatedCallback = undefined;
    this.removeAllListeners();
  }

  private flushStartupBuffer(): void {
    if (!this.processCreatedCallback) return;
    while (this.startupBuffer.length > 0) {
      const buffered = this.startupBuffer.shift()!;
      this.processCreatedCallback(buffered);
    }
  }

  /**
   * Simulates an inbound process creation event from the OS.
   */
  public emitEvent(event: ProcessCreationEvent): void {
    this.eventsObserved++;
    if (this.processCreatedCallback) {
      this.flushStartupBuffer();
      this.processCreatedCallback(event);
    } else {
      this.startupBuffer.push(event);
    }
    this.emit('processCreated', event);
  }

  /**
   * Simulates an unexpected failure in the event source.
   */
  public simulateFailure(err: Error): void {
    this.state = 'ERROR';
    this.lastError = err.message;
    this.emit('error', err);
  }
}
