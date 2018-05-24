import { createNamespace, getNamespace } from 'continuation-local-storage';
import { NextFunction, Request, Response } from 'express';
import * as shortid from 'shortid';

const RequestIdNamespaceName = 'requestIdNamespace';
export { RequestIdNamespaceName };
const requestIdNamespace = createNamespace(RequestIdNamespaceName);

function flattenWithInheritProperties(obj: object): object {
	const result = Object.create(obj);
	Object.getOwnPropertyNames(obj).forEach((key) => {
		result[key] = result[key];
	});
	return result;
}

export function requestIdFilter(level: string, msg: string, meta: any): string | { msg: any; meta: any; } {
	const formatLogInJSON: boolean = global.n9NodeRoutingData.formatLogInJSON;

	const namespaceRequestId = getNamespace(RequestIdNamespaceName);
	const requestId = namespaceRequestId && namespaceRequestId.get('requestId');
	if (formatLogInJSON) {
		const metaFull = flattenWithInheritProperties(meta);
		return {
			msg,
			meta: {
				...metaFull,
				requestId,
			},
		};
	} else {
		const messageWithRequestID = requestId ? `(${requestId}) ${msg}` : msg;
		return messageWithRequestID;
	}
}

export function setRequestContext(req: Request, res: Response, next: NextFunction): void {
	requestIdNamespace.run(() => {
		if (!req.headers.requestId) {
			req.headers.requestId = shortid.generate();
		}
		requestIdNamespace.set('requestId', req.headers.requestId);
		next();
	});
}
