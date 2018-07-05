// @flow

import _ from 'lodash';
import semver from 'semver';
import createError from 'http-errors';
import {allow} from '../../middleware';
import {DIST_TAGS, convertDistRemoteToLocalTarballUrls, getVersion, ErrorCode} from '../../../lib/utils';
import {HEADERS} from '../../../lib/constants';
import type {Router} from 'express';
import type {Config} from '@verdaccio/types';
import type {IAuth, $ResponseExtend, $RequestExtend, $NextFunctionVer, IStorageHandler} from '../../../../types';

export default function(route: Router, auth: IAuth, storage: IStorageHandler, config: Config) {
  const can = allow(auth);
  // TODO: anonymous user?
  route.get('/:package/:version?', can('access'), function(req: $RequestExtend, res: $ResponseExtend, next: $NextFunctionVer) {
    const getPackageMetaCallback = function(err, metadata) {
      if (err) {
        return next(err);
      }
      metadata = convertDistRemoteToLocalTarballUrls(metadata, req, config.url_prefix);

      // --- Mobiscroll ---
      // Allow access until a specific version only
      let latest = req.params.latest;
      if (_.isNil(latest) === false) {
        let versions = {};
        _.each(metadata.versions, function(val, vers) {
          if (semver.lte(vers, latest)) {
            versions[vers] = val;
          }
        });
        metadata[DIST_TAGS].latest = latest;
        metadata.versions = versions;
      }
      // ---

      let queryVersion = req.params.version;
      if (_.isNil(queryVersion)) {
        return next(metadata);
      }

      let version = getVersion(metadata, queryVersion);
      if (_.isNil(version) === false) {
        return next(version);
      }

      if (_.isNil(metadata[DIST_TAGS]) === false) {
        if (_.isNil(metadata[DIST_TAGS][queryVersion]) === false) {
          queryVersion = metadata[DIST_TAGS][queryVersion];
          version = getVersion(metadata, queryVersion);
          if (_.isNil(version) === false) {
            return next(version);
          }
        }
      }
      return next(ErrorCode.getNotFound(`version not found: ${req.params.version}`));
    };

    storage.getPackage({
      name: req.params.package,
      req,
      callback: getPackageMetaCallback,
    });
  });

  /* --- Mobiscroll ---
  route.get('/:package/-/:filename', can('access'), function(req: $RequestExtend, res: $ResponseExtend) {
    const stream = storage.getTarball(req.params.package, req.params.filename);

    stream.on('content-length', function(content) {
      res.header('Content-Length', content);
    });
    stream.on('error', function(err) {
      return res.report_error(err);
    });
    res.header('Content-Type', HEADERS.OCTET_STREAM);
    stream.pipe(res);
  });
  */

  route.get('/:package/-/:filename', can('access'), function(req: $RequestExtend, res: $ResponseExtend, next) {
    // --- Mobiscroll ---
    // Allow access until a specific version only
    let latest = req.params.latest;
    if (_.isNil(latest) === false) {
      let packageName = req.params.package.replace(/^@[^\/]*\//, '');
      let fileName = req.params.filename;
      let version = fileName.replace(packageName + '-', '').replace('.tgz', '');

      if (semver.gt(version, latest)) {
        return next(createError[403]('user is not allowed to access the package ' + fileName));
      }
    }

    auth.process_stream(
      req.params.package,
      req.params.filename,
      req.remote_user,
      storage.get_tarball(req.params.package, req.params.filename),
      function(err, stream) {
        if (err) {
          return res.report_error(err);
        }

        if (stream) {
          stream.on('content-length', function(v) {
            res.header('Content-Length', v);
          });
          stream.on('error', function(err) {
            return res.report_error(err);
          });
          stream.pipe(res);
        }
      }
    );
    // ---
  });
}
