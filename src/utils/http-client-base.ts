import { N9Log } from '@neo9/n9-node-log';
import { N9Error } from '@neo9/n9-node-utils';
import { getNamespace } from 'continuation-local-storage';
import fastSafeStringify from 'fast-safe-stringify';
import got, { Method, Options } from 'got';
import { IncomingMessage } from 'http';
import { PassThrough } from 'stream';
import urlJoin = require('url-join');
import { RequestIdNamespaceName } from '../requestid';

export type QueryParams = string | Record<string, string | number | boolean> | URLSearchParams;

export class N9HttpClient {
	private static getUriFromUrlParts(url: string | string[]): string {
		let uri;
		if (Array.isArray(url)) uri = urlJoin(...url);
		else uri = urlJoin(url);
		return uri;
	}

	private static prepareErrorCodeAndStatus(e: any): { code: string; status: number } {
		let code;
		try {
			const errorJson =
				typeof e.response?.body === 'object' ? e.response?.body : JSON.parse(e.response?.body);
			code = errorJson?.code;
		} catch (error) {
			code = e.code;
		}
		if (!code) code = e.code;

		const status = e.response?.statusCode;
		return { code, status };
	}

	constructor(
		private readonly logger: N9Log = global.log,
		private baseOptions: Options = {
			responseType: 'json',
			hooks: {
				beforeRetry: [
					(options, error, retryCount) => {
						logger.debug(
							`Retry call [${options.method} ${options.url}] n°${retryCount} due to ${error.name} ${error.message}`,
							{
								errString: fastSafeStringify(error),
							},
						);
					},
				],
			},
		},
		private maxBodyLengthToLogError: number = 100,
	) {}

	/**
	 * QueryParams samples : https://github.com/request/request/blob/master/tests/test-qs.js
	 */
	public async get<T>(
		url: string | string[],
		queryParams?: QueryParams,
		headers: object = {},
		options: Options = {},
	): Promise<T> {
		return this.request<T>('get', url, queryParams, headers, undefined, options);
	}

	public async post<T>(
		url: string | string[],
		body?: any,
		queryParams?: QueryParams,
		headers: object = {},
		options: Options = {},
	): Promise<T> {
		return this.request<T>('post', url, queryParams, headers, body, options);
	}

	public async put<T>(
		url: string | string[],
		body?: any,
		queryParams?: QueryParams,
		headers: object = {},
		options: Options = {},
	): Promise<T> {
		return this.request<T>('put', url, queryParams, headers, body, options);
	}

	public async delete<T>(
		url: string | string[],
		body?: any,
		queryParams?: QueryParams,
		headers: object = {},
		options: Options = {},
	): Promise<T> {
		return this.request<T>('delete', url, queryParams, headers, body, options);
	}

	public async options<T>(
		url: string | string[],
		queryParams?: QueryParams,
		headers: object = {},
		options: Options = {},
	): Promise<T> {
		return this.request<T>('options', url, queryParams, headers, undefined, options);
	}

	public async patch<T>(
		url: string | string[],
		body?: any,
		queryParams?: QueryParams,
		headers: object = {},
		options: Options = {},
	): Promise<T> {
		return this.request<T>('patch', url, queryParams, headers, body, options);
	}

	public async head(
		url: string | string[],
		queryParams?: QueryParams,
		headers: object = {},
		options: Options = {},
	): Promise<void> {
		return this.request<void>('head', url, queryParams, headers, undefined, options);
	}

	public async request<T>(
		method: Method,
		url: string | string[],
		queryParams?: string | Record<string, string | number | boolean> | URLSearchParams,
		headers: object = {},
		body?: any,
		options: Options = {},
	): Promise<T> {
		const uri = N9HttpClient.getUriFromUrlParts(url);

		const namespaceRequestId = getNamespace(RequestIdNamespaceName);
		const requestId = namespaceRequestId?.get('request-id');
		const sentHeaders = Object.assign({}, headers, { 'x-request-id': requestId });
		const startTime = Date.now();

		try {
			const optionsSent: Options = {
				method,
				searchParams: queryParams,
				headers: sentHeaders,
				json: body,
				resolveBodyOnly: false,
				...this.baseOptions,
				...options,
			};
			const res = await got<T>(uri, optionsSent as any);
			// console.log(`-- http-client-base.ts res --`, res);
			return res.body;
		} catch (e) {
			const responseTime = Date.now() - startTime;
			const bodyJSON = fastSafeStringify(body);
			const { code, status } = N9HttpClient.prepareErrorCodeAndStatus(e);
			this.logger.error(`Error on [${method} ${uri}]`, {
				'status': status,
				'response-time': responseTime,
			});

			throw new N9Error(code, status, {
				uri,
				method,
				queryParams,
				headers,
				responseTime,
				code: e.code,
				body: body && bodyJSON.length < this.maxBodyLengthToLogError ? bodyJSON : undefined,
				srcError: e.response?.body,
			});
		}
	}

	public async raw<T>(url: string | string[], options: Options): Promise<T> {
		const uri = N9HttpClient.getUriFromUrlParts(url);
		const startTime = Date.now();

		try {
			const res = await got<T>(uri, {
				resolveBodyOnly: false,
				...this.baseOptions,
				...options,
			} as any);

			return res.body;
		} catch (e) {
			const responseTime = Date.now() - startTime;
			const { code, status } = N9HttpClient.prepareErrorCodeAndStatus(e);
			this.logger.error(`Error on [${options.method} ${uri}]`, {
				status,
				'response-time': responseTime,
			});

			throw new N9Error(code, status, {
				uri,
				options: fastSafeStringify(options),
				error: e,
				...e.context,
			});
		}
	}

	public async requestStream(
		url: string | string[],
		options?: Options,
	): Promise<{ incomingMessage: IncomingMessage; responseAsStream: PassThrough }> {
		const responseAsStream = new PassThrough();
		const startTime = Date.now();
		const uri = N9HttpClient.getUriFromUrlParts(url);
		const requestResponse = await got.stream(uri, options);
		requestResponse.pipe(responseAsStream);

		let incomingMessage: IncomingMessage;
		let durationMsTTFB: number;
		try {
			incomingMessage = await new Promise<IncomingMessage>((resolve, reject) => {
				requestResponse.on('error', (err) => reject(err));
				requestResponse.on('response', (response) => {
					response.on('end', () => {
						const durationMsTTLB = Date.now() - startTime;
						if (durationMsTTFB !== null && durationMsTTFB !== undefined) {
							const durationDLMs = durationMsTTLB - durationMsTTFB;
							this.logger.debug(`File TTLB : ${durationMsTTLB} ms TTDL : ${durationDLMs} ms`, {
								durationDLMs,
								url,
								durationMs: durationMsTTLB,
							});
						} else {
							this.logger.debug(`File TTLB : ${durationMsTTLB} ms`, {
								url,
								durationMs: durationMsTTLB,
							});
						}
					});
					if (response.statusCode >= 400) {
						reject(response);
					}
					resolve(response);
				});
			});
		} catch (e) {
			const durationCatch = Date.now() - startTime;
			this.logger.error(`Error on [${options ? options.method || 'GET' : 'GET'} ${uri}]`, {
				'status': e.statusCode,
				'response-time': durationCatch,
			});
			this.logger.debug(`File TTFB : ${durationCatch} ms`, {
				url,
				durationMs: durationCatch,
				statusCode: e.statusCode,
			});
			const { code, status } = N9HttpClient.prepareErrorCodeAndStatus(e);

			throw new N9Error(code || 'unknown-error', status, {
				uri,
				method: options?.method,
				code: e.code || code,
				headers: options?.headers,
				srcError: e,
				responseTime: durationCatch,
			});
		}
		durationMsTTFB = Date.now() - startTime;
		this.logger.debug(`File TTFB : ${durationMsTTFB} ms`, {
			url,
			durationMs: durationMsTTFB,
			statusCode: incomingMessage.statusCode,
		});
		return { incomingMessage, responseAsStream };
	}
}
