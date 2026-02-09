import asyncio
from common.logger import getLogger
from oam_client import AsyncBrokerClient, BrokerClient
from oam_client.messages import Event, ServerAction
from asset_model import AssetType
from dnsdump.service import DumpDNSCommand

logger = getLogger(__name__)


class BrokerHandler:
    def __init__(
            self,
            client: AsyncBrokerClient,
    ):
        self.client = client

    async def handler(self, event: Event):
        logger.debug(f"handler:{event.action}:{event.data.type}")

        if event.action == ServerAction.EntityCreated \
           and event.data.type == AssetType.FQDN:
            try:
                cmd = DumpDNSCommand(
                    domain=event.data.asset.name,
                    store=self.client,
                    on_success=lambda rdtype, rdata: print("find:", rdtype, rdata),
                    on_failure=lambda rdtype: print("fail:", rdtype),
                )
                print(cmd)
                await cmd.run()
            except Exception as e:
                print(e)


async def async_main():
    client = AsyncBrokerClient("https://localhost", verify=False)
    handler = BrokerHandler(
        client=client
    )
    await client.listen_events(handler.handler)


def main():
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
