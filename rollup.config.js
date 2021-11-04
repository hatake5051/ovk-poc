import includePaths from 'rollup-plugin-includepaths';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import json from '@rollup/plugin-json';

export default {
  input: 'build/index.js',
  output: {
    file: 'bundle.js',
    format: 'cjs',
  },
  plugins: [json(), commonjs(), resolve(), includePaths({ paths: ['./build'] })],
};
