import { Get, JsonController } from '@flyacts/routing-controllers';
import { N9Log } from '@neo9/n9-node-log';
import { N9Error } from '@neo9/n9-node-utils';
import { Inject, Service } from 'typedi';

@Service()
@JsonController()
export class ErrorsController {
	@Inject('logger')
	private logger: N9Log;
	@Get('/503')
	public async getError500(): Promise<any> {
		this.logger.error(`An error occurred, client should retry`);
		throw new N9Error('an-error', 503);
	}
}
