import * as pulumi from '@pulumi/pulumi';

import type { BucketConfig, Settings, UserConfig } from './configGuard';
import { buildStack } from './stack';

const config = new pulumi.Config();

const settings: Settings = {
  allowedProjectId: config.require('allowedProjectId'),
  nameSuffix: config.get('nameSuffix'),
  users: config.getObject<UserConfig[]>('users') ?? [],
  buckets: config.requireObject<BucketConfig[]>('buckets'),
};

const stack = buildStack(settings, process.env);

export const bucketNames = Object.keys(stack.buckets);
export const s3Endpoints = stack.s3Endpoints;
export const accessKeyIds = stack.accessKeyIds;
export const secretAccessKeys = stack.secretAccessKeys;
