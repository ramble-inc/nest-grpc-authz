import { MetadataWithClaim } from './auth.interface';

export const isMetadataWithClaim = (
  value: unknown,
): value is MetadataWithClaim => {
  return (
    typeof value === 'object' &&
    (value as MetadataWithClaim).claim !== undefined
  );
};
