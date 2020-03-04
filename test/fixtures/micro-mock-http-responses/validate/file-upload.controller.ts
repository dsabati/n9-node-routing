import { JsonController, Post, UploadedFile } from '@flyacts/routing-controllers';
import * as fs from 'fs';
import * as multer from 'multer';
import { PassThrough } from 'stream';
import { Service } from 'typedi';

// to keep code clean better to extract this function into separate file
class StorageEngine implements multer.StorageEngine {
	public _handleFile(req: any, file: any, cb: any): void {
		cb(null, { mimetype: file.mimetype, stream: file.stream.pipe(new PassThrough()) });
	}

	public _removeFile(req: any, file: any, cb: any): void {
		cb();
	}
}

const fileUploadOptions = () => ({
	storage: new StorageEngine(),
});

@Service()
@JsonController()
export class ErrorsController {
	// use options this way:
	@Post('/files')
	public async saveFile(
		@UploadedFile('file1', { options: fileUploadOptions() })
		file: {
			stream: PassThrough;
			mimeType: string;
		},
	): Promise<any> {
		const outStream = fs.createWriteStream('/dev/null');
		let size = 0;

		return await new Promise((resolve, reject) => {
			file.stream.on('data', (chunk) => (size += chunk.length)).pipe(outStream);
			outStream.on('error', reject).on('finish', () => {
				resolve({
					size,
					bytesWritten: outStream.bytesWritten,
				});
			});
		});
	}
}
