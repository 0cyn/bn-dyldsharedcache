from binaryninja import *
from binaryninjaui import *

from .dsc import DyldSharedCacheView

DyldSharedCacheView.register()

class DSCViewWatcher(UIContextNotification):
	def __init__(self):
		UIContextNotification.__init__(self)
		UIContext.registerNotification(self)
		print("py UIContext.registerNotification")

	def __del__(self):
		UIContext.unregisterNotification(self)
		print("py UIContext.unregisterNotification")

	def OnAfterOpenFile(self, context, file, frame):
		# We only want to auto-switch DyldSharedCache views
		if "DyldSharedCache" not in frame.getCurrentView():
			return

		# Get the current BinaryView and setup the Mach-O view so we can use  it
		view = frame.getCurrentBinaryView()
		view.file.get_view_of_type('Mach-O')

		# Switch to the Mach-O view now that the file has finished loading
		mainthread.execute_on_main_thread(lambda: frame.setViewType("Linear:Mach-O"))

# Register the view watcher globally so newly-created DSC views can be
# automatically switched to Mach-O after opening. This must be a global
# variable so it is not destroyed.
watcher = DSCViewWatcher()
