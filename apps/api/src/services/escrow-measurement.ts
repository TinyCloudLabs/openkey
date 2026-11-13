import { createHash } from 'node:crypto';
import { parseDocument } from 'yaml';

export interface EscrowMeasurement {
  appId: string; imageDigest: string; composeHash: string; codeHash: string;
  osVersion: string; agentVersion: string; bootReference: string;
}

/** Metadata read from the guest agent and measured compose, never from HTTP input. */
export function escrowMeasurementFromInfo(input: unknown, codeHash: unknown, bootId: string, agentVersion: string): EscrowMeasurement {
  if (!input || typeof input !== 'object') throw new Error('Guest info unavailable');
  const info = input as Record<string, unknown>;
  const tcb = info.tcb_info as Record<string, unknown> | undefined;
  if (typeof info.app_id !== 'string' || !/^[a-f0-9]{40}$/.test(info.app_id)
    || typeof info.compose_hash !== 'string' || !/^[a-f0-9]{64}$/.test(info.compose_hash)
    || !tcb || tcb.compose_hash !== info.compose_hash || typeof tcb.app_compose !== 'string'
    || typeof codeHash !== 'string' || !/^[a-f0-9]{64}$/.test(codeHash)
    || typeof info.instance_id !== 'string' || !/^[a-f0-9]+$/.test(info.instance_id)
    || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(bootId)
    || typeof agentVersion !== 'string' || !agentVersion) throw new Error('Invalid escrow measurement');
  if (createHash('sha256').update(tcb.app_compose, 'utf8').digest('hex') !== info.compose_hash) throw new Error('Measured compose hash mismatch');
  const compose = JSON.parse(tcb.app_compose);
  if (compose.runner !== 'docker-compose' || typeof compose.docker_compose_file !== 'string') throw new Error('Unsupported measured compose');
  const document = parseDocument(compose.docker_compose_file, { uniqueKeys: true });
  if (document.errors.length) throw new Error('Invalid measured compose');
  const docker = document.toJS({ maxAliasCount: 0 });
  if (!docker?.services || typeof docker.services !== 'object' || Array.isArray(docker.services)) throw new Error('Missing measured services');
  const services = Object.values(docker.services) as { image?: unknown; build?: unknown }[];
  if (!services.length) throw new Error('Missing measured services');
  for (const service of services) {
    if (!service || typeof service.image !== 'string' || !/^[^\s]+@sha256:[a-f0-9]{64}$/.test(service.image) || service.build !== undefined) throw new Error('Every image must be digest pinned');
  }
  const api = docker.services.api;
  if (!api || typeof api.image !== 'string') throw new Error('Missing API image');
  const osHash = tcb.os_image_hash;
  if (typeof osHash !== 'string' || !/^[a-f0-9]{64}$/.test(osHash)) throw new Error('Missing OS measurement');
  return { appId: info.app_id, imageDigest: api.image.slice(api.image.lastIndexOf('@') + 1), composeHash: info.compose_hash,
    codeHash, osVersion: `os-image-sha256:${osHash}`, agentVersion,
    bootReference: `instance:${info.instance_id};kernel-boot:${bootId}` };
}
