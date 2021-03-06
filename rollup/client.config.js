import commonjs from '@rollup/plugin-commonjs';
import json from '@rollup/plugin-json';
import resolve from '@rollup/plugin-node-resolve';
import includePaths from 'rollup-plugin-includepaths';

export default {
  input: 'build/entrypoint/client.js',
  output: {
    file: 'publish/client.js',
    format: 'es',
  },
  plugins: [json(), commonjs(), resolve(), includePaths({ paths: ['./build'] })],
};
