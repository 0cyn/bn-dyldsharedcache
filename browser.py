import binaryninjaui
from binaryninjaui import FilteredView, FilterTarget

from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QLabel,
    QListView,
    QPushButton,
    QVBoxLayout,
)

from PySide6.QtCore import Qt, QModelIndex, QStringListModel


class ImageListView(QListView, FilterTarget):
    def __init__(self, parent, images):
        QListView.__init__(self, parent)
        FilterTarget.__init__(self)

        self.img_list = images
        self.model = QStringListModel()
        self.model.setStringList(self.img_list)
        self.setModel(self.model)

        # Disable item editing and use the user's mono font
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setFont(binaryninjaui.getMonospaceFont(self))

    def selectedImage(self):
        index = self.selectionModel().currentIndex()

        if not index.isValid():
            return None

        return self.model.stringList()[index.row()]

    def setFilter(self, search):
        if len(search) == 0:
            self.model.setStringList(self.img_list)
            return

        # TODO: Perform case-insensitive filtering
        filtered_list = filter(lambda s: search in s, self.img_list)
        self.model.setStringList(filtered_list)

    def scrollToFirstItem(self):
        self.scrollToTop()

    def scrollToCurrentItem(self):
        self.scrollTo(self.currentIndex())

    def selectFirstItem(self):
        self.setCurrentIndex(self.model.index(0, 0, QModelIndex()))

    def activateFirstItem(self):
        self.exportDoubleClicked(self.model.index(0, 0, QModelIndex()))

    def closeFilter(self):
        self.setFocus(Qt.OtherFocusReason)


class ImagePickerDialog(QDialog):
    def __init__(self, images):
        super().__init__()

        self.imageView = ImageListView(self, images)
        filterView = FilteredView(self, self.imageView, self.imageView)

        infoLabel = QLabel(f"{len(images)} images available")
        cancelButton = QPushButton("Cancel")
        self.chooseButton = QPushButton("Choose")
        self.chooseButton.setDefault(True)

        # Disable the "Choose" button until a selection is made. This is hacky, but...
        self.chooseButton.setEnabled(False)
        self.imageView.selectionModel().selectionChanged.connect(
            lambda: self.chooseButton.setEnabled(True)
        )

        bottomLayout = QHBoxLayout()
        bottomLayout.addWidget(infoLabel)
        bottomLayout.addStretch(1)
        bottomLayout.addWidget(cancelButton)
        bottomLayout.addWidget(self.chooseButton)

        rootLayout = QVBoxLayout(self)
        rootLayout.addWidget(filterView)
        rootLayout.addLayout(bottomLayout)

        cancelButton.clicked.connect(self.reject)
        self.chooseButton.clicked.connect(self.accept)

        filterView.showFilter("")

        self.setMinimumSize(500, 400)
        self.setWindowTitle("Choose Image")

    def reject(self):
        self.chosen_image = None
        QDialog.reject(self)

    def accept(self):
        self.chosen_image = self.imageView.selectedImage()
        QDialog.accept(self)

    def run(self):
        self.exec()
